"""
Core P2P: discovery via broadcast UDP, handshake X25519,
invio/ricezione di messaggi testuali e file cifrati con AES-GCM,
e lifecycle dei peer (aggiunta + rimozione per inattività).

Nessun riferimento alla UI qui dentro: comunica verso l'esterno
solo tramite le tre callback passate al costruttore.
"""

import socket
import threading
import json
import base64
import os
import time

import crypto_utils
from logger_setup import setup_logging
from network_utils import get_broadcast_address, recv_exact

LISTEN_PORT = 9999
DISCOVERY_PORT = 9998
ANNOUNCE_INTERVAL = 3          # secondi tra un broadcast e l'altro
PEER_TIMEOUT = 10              # secondi di silenzio prima di considerare un peer offline
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB, limite di sicurezza per questo prototipo


class PeerNode:
    def __init__(self, hostname, on_peer_update, on_message, on_log):
        """
        on_peer_update(dict)      -> chiamata quando la lista peer cambia (aggiunta o rimozione)
        on_message(sender, text)  -> chiamata quando arriva un messaggio o un file
        on_log(level, msg)        -> chiamata per specchiare i log anche su una UI
        """
        self.hostname = hostname
        self.logger, self.log_filepath = setup_logging(hostname)
        self.broadcast_addr = get_broadcast_address()

        self.known_peers = {}  # hostname -> (ip, last_seen_timestamp)
        self.lock = threading.Lock()

        self.on_peer_update = on_peer_update
        self.on_message = on_message
        self.on_log = on_log

        self.private_key, self.public_key = crypto_utils.generate_keypair()

    # ---------------- logging ----------------

    def log(self, level, msg):
        getattr(self.logger, level)(msg)
        self.on_log(level, msg)

    # ---------------- discovery ----------------

    def announce_presence(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        msg = json.dumps({'type': 'announce', 'hostname': self.hostname}).encode()

        while True:
            try:
                sock.sendto(msg, (self.broadcast_addr, DISCOVERY_PORT))
                if self.broadcast_addr != '255.255.255.255':
                    sock.sendto(msg, ('255.255.255.255', DISCOVERY_PORT))
            except OSError as e:
                self.log('warning', f"Broadcast fallito: {e}")
            time.sleep(ANNOUNCE_INTERVAL)

    def listen_discovery(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            sock.bind(('', DISCOVERY_PORT))
        except OSError as e:
            self.log('critical', f"Impossibile bindare porta discovery {DISCOVERY_PORT}: {e}")
            return

        self.log('info', f"Discovery UDP attivo su porta {DISCOVERY_PORT}")

        while True:
            try:
                data, addr = sock.recvfrom(1024)
                msg = json.loads(data.decode())
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue

            if msg.get('type') != 'announce':
                continue

            peer_host = msg.get('hostname')
            peer_ip = addr[0]
            if not peer_host or peer_host == self.hostname:
                continue

            with self.lock:
                prev = self.known_peers.get(peer_host)
                is_new_or_changed = prev is None or prev[0] != peer_ip
                self.known_peers[peer_host] = (peer_ip, time.time())

            if is_new_or_changed:
                self.log('info', f"Peer scoperto: '{peer_host}' -> {peer_ip}")
                self.on_peer_update(self.get_peers_snapshot())

    def prune_dead_peers(self):
        """Rimuove periodicamente i peer che non annunciano da più di PEER_TIMEOUT secondi."""
        while True:
            time.sleep(2)
            now = time.time()
            removed = []
            with self.lock:
                for host in list(self.known_peers.keys()):
                    _, last_seen = self.known_peers[host]
                    if now - last_seen > PEER_TIMEOUT:
                        del self.known_peers[host]
                        removed.append(host)

            if removed:
                for host in removed:
                    self.log('warning', f"Peer '{host}' rimosso (inattivo da {PEER_TIMEOUT}s)")
                self.on_peer_update(self.get_peers_snapshot())

    def get_peers_snapshot(self):
        with self.lock:
            return dict(self.known_peers)

    def resolve(self, hostname):
        with self.lock:
            entry = self.known_peers.get(hostname)
            return entry[0] if entry else None

    # ---------------- listener P2P (in ingresso) ----------------

    def listen_p2p(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(('0.0.0.0', LISTEN_PORT))
            srv.listen(5)
        except OSError as e:
            self.log('critical', f"Impossibile bindare porta P2P {LISTEN_PORT}: {e}")
            return

        self.log('info', f"Nodo '{self.hostname}' in ascolto TCP su porta {LISTEN_PORT}")

        while True:
            try:
                conn, addr = srv.accept()
                threading.Thread(
                    target=self._handle_incoming, args=(conn, addr),
                    name=f"Handler-{addr[0]}", daemon=True
                ).start()
            except OSError as e:
                self.log('error', f"Errore accept: {e}")

    def _handle_incoming(self, conn, addr):
        try:
            conn.settimeout(15)

            their_pubkey_bytes = conn.recv(32)
            conn.send(crypto_utils.pubkey_to_bytes(self.public_key))
            shared_key = crypto_utils.derive_shared_key(self.private_key, their_pubkey_bytes)
            self.log('info', f"Handshake completato con {addr}")

            length_header = recv_exact(conn, 8)
            payload_len = int.from_bytes(length_header, 'big')
            raw_payload = recv_exact(conn, payload_len)

            packet = json.loads(raw_payload.decode())
            nonce = base64.b64decode(packet['nonce'])
            ciphertext = base64.b64decode(packet['ciphertext'])
            sender = packet.get('from', addr[0])

            plaintext_bytes = crypto_utils.decrypt(shared_key, nonce, ciphertext)

            if packet.get('type') == 'file':
                self._save_received_file(sender, packet.get('filename', 'file_ricevuto.bin'), plaintext_bytes)
            else:
                self.log('info', f"Messaggio ricevuto da '{sender}'")
                self.on_message(sender, plaintext_bytes.decode())

        except Exception as e:
            self.log('error', f"Errore gestendo {addr}: {type(e).__name__}: {e}")
        finally:
            conn.close()

    def _save_received_file(self, sender, filename, file_bytes):
        save_dir = os.path.join(os.path.expanduser("~"), "p2p_received_files")
        os.makedirs(save_dir, exist_ok=True)
        save_path = os.path.join(save_dir, filename)

        base, ext = os.path.splitext(save_path)
        counter = 1
        while os.path.exists(save_path):
            save_path = f"{base}_{counter}{ext}"
            counter += 1

        with open(save_path, 'wb') as f:
            f.write(file_bytes)

        self.log('info', f"File ricevuto da '{sender}': salvato in {save_path}")
        self.on_message(sender, f"[FILE] {filename} salvato in {save_path}")

    # ---------------- invio (in uscita) ----------------

    def _send_packet(self, target_hostname, packet_dict, log_label):
        target_ip = self.resolve(target_hostname)
        if not target_ip:
            self.log('warning', f"Hostname '{target_hostname}' sconosciuto")
            return False, "hostname sconosciuto"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        try:
            sock.connect((target_ip, LISTEN_PORT))
            sock.send(crypto_utils.pubkey_to_bytes(self.public_key))
            their_pubkey_bytes = sock.recv(32)
            shared_key = crypto_utils.derive_shared_key(self.private_key, their_pubkey_bytes)

            payload = json.dumps(packet_dict).encode()
            sock.send(len(payload).to_bytes(8, 'big'))
            sock.sendall(payload)

            self.log('info', f"{log_label} inviato a '{target_hostname}'")
            return True, None
        except Exception as e:
            self.log('error', f"Invio a {target_hostname} fallito: {e}")
            return False, str(e)
        finally:
            sock.close()

    def send_message(self, target_hostname, message):
        target_ip = self.resolve(target_hostname)
        if not target_ip:
            return False, "hostname sconosciuto"

        # handshake + cifratura fatti qui per poter derivare shared_key su questo scambio specifico
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((target_ip, LISTEN_PORT))
            sock.send(crypto_utils.pubkey_to_bytes(self.public_key))
            their_pubkey_bytes = sock.recv(32)
            shared_key = crypto_utils.derive_shared_key(self.private_key, their_pubkey_bytes)

            nonce, ciphertext = crypto_utils.encrypt(shared_key, message.encode())
            packet = {
                'type': 'text',
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'from': self.hostname
            }
            payload = json.dumps(packet).encode()
            sock.send(len(payload).to_bytes(8, 'big'))
            sock.sendall(payload)

            self.log('info', f"Messaggio inviato a '{target_hostname}'")
            return True, None
        except Exception as e:
            self.log('error', f"Invio a {target_hostname} fallito: {e}")
            return False, str(e)
        finally:
            sock.close()

    def send_file(self, target_hostname, filepath):
        if not os.path.isfile(filepath):
            self.log('error', f"File non trovato: {filepath}")
            return False, "file non trovato"

        filesize = os.path.getsize(filepath)
        if filesize > MAX_FILE_SIZE:
            self.log('warning', f"File troppo grande ({filesize} byte), limite {MAX_FILE_SIZE}")
            return False, "file troppo grande per questo prototipo"

        target_ip = self.resolve(target_hostname)
        if not target_ip:
            return False, "hostname sconosciuto"

        filename = os.path.basename(filepath)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect((target_ip, LISTEN_PORT))
            sock.send(crypto_utils.pubkey_to_bytes(self.public_key))
            their_pubkey_bytes = sock.recv(32)
            shared_key = crypto_utils.derive_shared_key(self.private_key, their_pubkey_bytes)

            with open(filepath, 'rb') as f:
                file_bytes = f.read()

            nonce, ciphertext = crypto_utils.encrypt(shared_key, file_bytes)
            packet = {
                'type': 'file',
                'filename': filename,
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'from': self.hostname
            }
            payload = json.dumps(packet).encode()
            sock.send(len(payload).to_bytes(8, 'big'))
            sock.sendall(payload)

            self.log('info', f"File '{filename}' ({filesize} byte) inviato a '{target_hostname}'")
            return True, None
        except Exception as e:
            self.log('error', f"Invio file a {target_hostname} fallito: {e}")
            return False, str(e)
        finally:
            sock.close()

    # ---------------- lifecycle ----------------

    def start(self):
        threading.Thread(target=self.listen_discovery, name="DiscoveryListener", daemon=True).start()
        threading.Thread(target=self.announce_presence, name="Announcer", daemon=True).start()
        threading.Thread(target=self.listen_p2p, name="P2PListener", daemon=True).start()
        threading.Thread(target=self.prune_dead_peers, name="PeerPruner", daemon=True).start()
