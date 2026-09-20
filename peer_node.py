"""
Core P2P: discovery via broadcast UDP (LAN), handshake X25519,
invio/ricezione di messaggi testuali e file cifrati con AES-GCM,
lifecycle dei peer, verifica di integrità via SHA-256, progress
callback per invii grandi, e routing ibrido: se il target non è
raggiungibile in LAN, tenta l'invio tramite Relay Server (fuori
rete locale), usando i contatti salvati via contact card.
Invio file supportato sia via LAN che via relay.
"""

import socket
import threading
import json
import base64
import os
import time
import hashlib

import crypto_utils
from logger_setup import setup_logging
from network_utils import get_broadcast_address, recv_exact
from transfer_log import TransferLog
from message_log import MessageLog
from app_paths import received_dir_for_peer
from identity import get_or_create_identity
from relay_client import RelayClient
from contacts import ContactsStore
from contact_card import create_card, parse_card

LISTEN_PORT = 9999
DISCOVERY_PORT = 9998
ANNOUNCE_INTERVAL = 3
PEER_TIMEOUT = 10
MAX_FILE_SIZE = 20 * 1024 * 1024
SEND_CHUNK = 64 * 1024

# Cambia in "p2p-relay-stefano.fly.dev" quando pronto per il deploy reale su Fly.io
RELAY_HOST = "p2p-relay-stefano.fly.dev"
RELAY_PORT = 8443


class PeerNode:
    def __init__(self, hostname, on_peer_update, on_message, on_log):
        self.hostname = hostname
        self.logger, self.log_filepath = setup_logging(hostname)
        self.broadcast_addr = get_broadcast_address()

        self.known_peers = {}
        self.lock = threading.Lock()

        self.on_peer_update = on_peer_update
        self.on_message = on_message
        self.on_log = on_log

        self.x25519_private_key, self.ed25519_private_key = get_or_create_identity()
        self.private_key = self.x25519_private_key
        self.public_key = self.x25519_private_key.public_key()

        self.transfer_log = TransferLog()
        self.message_log = MessageLog()
        self.contacts = ContactsStore()
        self.relay_client = None

    def log(self, level, msg):
        getattr(self.logger, level)(msg)
        self.on_log(level, msg)

    # ---------------- identità / contatti remoti ----------------

    def get_my_contact_card(self):
        return create_card(self.hostname, self.ed25519_private_key, self.x25519_private_key)

    def add_contact_from_card(self, card_string):
        try:
            parsed = parse_card(card_string)
        except ValueError as e:
            return False, str(e)

        self.contacts.add_contact(
            parsed['hostname'],
            parsed['ed25519_pub_hex'],
            parsed['x25519_pub_bytes'].hex()
        )
        self.log('info', f"Contatto remoto aggiunto: '{parsed['hostname']}'")
        return True, parsed['hostname']

    # ---------------- discovery LAN ----------------

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

    def announce_goodbye(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        msg = json.dumps({'type': 'goodbye', 'hostname': self.hostname}).encode()
        try:
            sock.sendto(msg, (self.broadcast_addr, DISCOVERY_PORT))
            sock.sendto(msg, ('255.255.255.255', DISCOVERY_PORT))
            self.log('info', "Annuncio di uscita inviato")
        except OSError as e:
            self.log('warning', f"Impossibile inviare goodbye: {e}")
        finally:
            sock.close()

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

            msg_type = msg.get('type')

            if msg_type == 'goodbye':
                peer_host = msg.get('hostname')
                if peer_host and peer_host != self.hostname:
                    with self.lock:
                        existed = peer_host in self.known_peers
                        if existed:
                            del self.known_peers[peer_host]
                    if existed:
                        self.log('info', f"Peer '{peer_host}' uscito volontariamente")
                        self.on_peer_update(self.get_peers_snapshot())
                continue

            if msg_type != 'announce':
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

    # ---------------- listener P2P LAN (in ingresso) ----------------

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
            conn.settimeout(30)

            their_pubkey_bytes = conn.recv(32)
            conn.send(crypto_utils.pubkey_to_bytes(self.public_key))
            shared_key = crypto_utils.derive_shared_key(self.private_key, their_pubkey_bytes)
            self.log('info', f"Handshake completato con {addr}")

            length_header = recv_exact(conn, 8)
            payload_len = int.from_bytes(length_header, 'big')
            raw_payload = recv_exact(conn, payload_len)

            packet = json.loads(raw_payload.decode())
            self._process_decrypted_packet(packet, shared_key, sender_hint=addr)

        except Exception as e:
            self.log('error', f"Errore gestendo {addr}: {type(e).__name__}: {e}")
        finally:
            conn.close()

    def _handle_relay_message(self, from_pubkey_hex, payload_dict):
        try:
            packet = payload_dict
            sender_x25519_pub_bytes = bytes.fromhex(packet['sender_x25519_pub'])
            shared_key = crypto_utils.derive_shared_key(self.x25519_private_key, sender_x25519_pub_bytes)
            self._process_decrypted_packet(packet, shared_key, sender_hint=f"relay:{from_pubkey_hex[:12]}")
        except Exception as e:
            self.log('error', f"Errore gestendo pacchetto relay da {from_pubkey_hex[:12]}...: {e}")

    def _process_decrypted_packet(self, packet, shared_key, sender_hint):
        nonce = base64.b64decode(packet['nonce'])
        ciphertext = base64.b64decode(packet['ciphertext'])
        sender = packet.get('from', str(sender_hint))

        plaintext_bytes = crypto_utils.decrypt(shared_key, nonce, ciphertext)

        if packet.get('type') == 'file':
            name_len = int.from_bytes(plaintext_bytes[:2], 'big')
            offset = 2
            filename = plaintext_bytes[offset:offset + name_len].decode('utf-8')
            offset += name_len
            expected_hash = plaintext_bytes[offset:offset + 64].decode('utf-8')
            offset += 64
            file_content = plaintext_bytes[offset:]

            actual_hash = hashlib.sha256(file_content).hexdigest()
            if actual_hash != expected_hash:
                self.log('error', f"Hash mismatch per file da '{sender}'")
                self.on_message(sender, f"[FILE CORROTTO] {filename} — verifica integrità fallita")
                return

            self._save_received_file(sender, filename, file_content)
        else:
            self.log('info', f"Messaggio ricevuto da '{sender}'")
            self.message_log.add_entry('received', sender, plaintext_bytes.decode())
            self.on_message(sender, plaintext_bytes.decode())

    def _save_received_file(self, sender, filename, file_bytes):
        save_dir = received_dir_for_peer(sender)
        save_path = os.path.join(save_dir, filename)

        base, ext = os.path.splitext(save_path)
        counter = 1
        while os.path.exists(save_path):
            save_path = f"{base}_{counter}{ext}"
            counter += 1

        with open(save_path, 'wb') as f:
            f.write(file_bytes)

        self.log('info', f"File ricevuto da '{sender}': salvato in {save_path}")
        self.transfer_log.add_entry('received', sender, filename, save_path, len(file_bytes))
        self.on_message(sender, f"[FILE] {filename} salvato in {save_path}")

    # ---------------- relay (fuori LAN) ----------------

    def _start_relay(self):
        def relay_loop():
            while True:
                self.relay_client = RelayClient(
                    RELAY_HOST, RELAY_PORT,
                    self.x25519_private_key, self.ed25519_private_key,
                    self.hostname,
                    on_relay_message=self._handle_relay_message,
                    on_log=self.on_log
                )
                if self.relay_client.connect_and_authenticate():
                    self.relay_client.start()
                    self.log('info', "Connesso al relay server")
                    while self.relay_client.connected:
                        time.sleep(1)
                    self.log('warning', "Connessione relay persa, riconnessione tra 5s...")
                else:
                    self.log('warning', "Autenticazione relay fallita, riprovo tra 5s...")
                time.sleep(5)

        threading.Thread(target=relay_loop, name="RelayConnection", daemon=True).start()

    # ---------------- invio messaggi (routing ibrido) ----------------

    def send_message(self, target_hostname, message):
        target_ip = self.resolve(target_hostname)
        if target_ip:
            return self._send_message_lan(target_hostname, target_ip, message)

        ed25519_pub_hex, x25519_pub_hex = self.contacts.get_by_hostname(target_hostname)
        if ed25519_pub_hex:
            return self._send_message_relay(target_hostname, ed25519_pub_hex, x25519_pub_hex, message)

        return False, "hostname sconosciuto (né in LAN né tra i contatti remoti)"

    def _send_message_lan(self, target_hostname, target_ip, message):
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

            self.log('info', f"Messaggio inviato a '{target_hostname}' (via LAN)")
            self.message_log.add_entry('sent', target_hostname, message)
            return True, None
        except Exception as e:
            self.log('error', f"Invio LAN a {target_hostname} fallito: {e}")
            return False, str(e)
        finally:
            sock.close()

    def _send_message_relay(self, target_hostname, target_ed25519_pub_hex, target_x25519_pub_hex, message):
        if not self.relay_client or not self.relay_client.connected:
            return False, "non connesso al relay server"

        online, _ = self.relay_client.lookup(target_ed25519_pub_hex)
        if not online:
            return False, f"'{target_hostname}' non è online sul relay al momento"

        target_x25519_pub_bytes = bytes.fromhex(target_x25519_pub_hex)
        shared_key = crypto_utils.derive_shared_key(self.x25519_private_key, target_x25519_pub_bytes)

        nonce, ciphertext = crypto_utils.encrypt(shared_key, message.encode())
        packet = {
            'type': 'text',
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'from': self.hostname,
            'sender_x25519_pub': crypto_utils.pubkey_to_bytes(self.x25519_private_key.public_key()).hex()
        }

        ok = self.relay_client.send_relay(target_ed25519_pub_hex, packet)
        if ok:
            self.log('info', f"Messaggio inviato a '{target_hostname}' (via relay)")
            self.message_log.add_entry('sent', target_hostname, message)
            return True, None
        return False, "invio relay fallito"

    # ---------------- invio file (routing ibrido) ----------------

    def send_file(self, target_hostname, filepath, on_progress=None):
        if not os.path.isfile(filepath):
            self.log('error', f"File non trovato: {filepath}")
            return False, "file non trovato"

        filesize = os.path.getsize(filepath)
        if filesize > MAX_FILE_SIZE:
            self.log('warning', f"File troppo grande ({filesize} byte), limite {MAX_FILE_SIZE}")
            return False, "file troppo grande per questo prototipo"

        target_ip = self.resolve(target_hostname)
        if target_ip:
            return self._send_file_lan(target_hostname, target_ip, filepath, filesize, on_progress)

        ed25519_pub_hex, x25519_pub_hex = self.contacts.get_by_hostname(target_hostname)
        if ed25519_pub_hex:
            return self._send_file_relay(target_hostname, ed25519_pub_hex, x25519_pub_hex, filepath, filesize, on_progress)

        return False, "hostname sconosciuto (né in LAN né tra i contatti remoti)"

    def _build_file_blob(self, filename, filepath):
        """Costruisce il blob [len_nome][nome][hash][contenuto], condiviso da LAN e relay."""
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        filename_bytes = filename.encode('utf-8')
        if len(filename_bytes) > 65535:
            raise ValueError("Nome file troppo lungo")
        name_len_header = len(filename_bytes).to_bytes(2, 'big')
        return name_len_header + filename_bytes + file_hash.encode('utf-8') + file_bytes

    def _send_file_lan(self, target_hostname, target_ip, filepath, filesize, on_progress):
        filename = os.path.basename(filepath)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(60)
        try:
            sock.connect((target_ip, LISTEN_PORT))
            sock.send(crypto_utils.pubkey_to_bytes(self.public_key))
            their_pubkey_bytes = sock.recv(32)
            shared_key = crypto_utils.derive_shared_key(self.private_key, their_pubkey_bytes)

            combined = self._build_file_blob(filename, filepath)
            nonce, ciphertext = crypto_utils.encrypt(shared_key, combined)
            packet = {
                'type': 'file',
                'nonce': base64.b64encode(nonce).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'from': self.hostname
            }
            payload = json.dumps(packet).encode()
            total_len = len(payload)
            sock.send(total_len.to_bytes(8, 'big'))

            sent = 0
            while sent < total_len:
                chunk = payload[sent:sent + SEND_CHUNK]
                sock.sendall(chunk)
                sent += len(chunk)
                if on_progress:
                    on_progress(sent, total_len)

            self.log('info', f"File '{filename}' ({filesize} byte) inviato a '{target_hostname}' (via LAN)")
            self.transfer_log.add_entry('sent', target_hostname, filename, filepath, filesize)
            return True, None
        except Exception as e:
            self.log('error', f"Invio file LAN a {target_hostname} fallito: {e}")
            return False, str(e)
        finally:
            sock.close()

    def _send_file_relay(self, target_hostname, target_ed25519_pub_hex, target_x25519_pub_hex, filepath, filesize, on_progress):
        if not self.relay_client or not self.relay_client.connected:
            return False, "non connesso al relay server"

        online, _ = self.relay_client.lookup(target_ed25519_pub_hex)
        if not online:
            return False, f"'{target_hostname}' non è online sul relay al momento"

        filename = os.path.basename(filepath)
        target_x25519_pub_bytes = bytes.fromhex(target_x25519_pub_hex)
        shared_key = crypto_utils.derive_shared_key(self.x25519_private_key, target_x25519_pub_bytes)

        try:
            combined = self._build_file_blob(filename, filepath)
        except ValueError as e:
            return False, str(e)

        nonce, ciphertext = crypto_utils.encrypt(shared_key, combined)
        packet = {
            'type': 'file',
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'from': self.hostname,
            'sender_x25519_pub': crypto_utils.pubkey_to_bytes(self.x25519_private_key.public_key()).hex()
        }

        if on_progress:
            on_progress(1, 1)  # invio atomico via relay, niente progress granulare per ora

        ok = self.relay_client.send_relay(target_ed25519_pub_hex, packet)
        if ok:
            self.log('info', f"File '{filename}' ({filesize} byte) inviato a '{target_hostname}' (via relay)")
            self.transfer_log.add_entry('sent', target_hostname, filename, filepath, filesize)
            return True, None
        return False, "invio file via relay fallito"

    # ---------------- lifecycle ----------------

    def start(self):
        threading.Thread(target=self.listen_discovery, name="DiscoveryListener", daemon=True).start()
        threading.Thread(target=self.announce_presence, name="Announcer", daemon=True).start()
        threading.Thread(target=self.listen_p2p, name="P2PListener", daemon=True).start()
        threading.Thread(target=self.prune_dead_peers, name="PeerPruner", daemon=True).start()
        self._start_relay()
