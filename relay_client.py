"""
Client per il Rendezvous + Relay Server.

Gestisce: connessione al server, autenticazione challenge-response
tramite firma Ed25519, lookup di altri nodi, invio/ricezione di
pacchetti relay (già cifrati E2EE a livello applicativo — questo
client non fa cifratura, solo trasporto verso/dal server).
"""

import socket
import threading
import json
import base64
import time


class RelayClient:
    def __init__(self, server_host, server_port, x25519_private_key, ed25519_private_key,
                 hostname, on_relay_message, on_log):
        self.server_host = server_host
        self.server_port = server_port
        self.x25519_private_key = x25519_private_key
        self.ed25519_private_key = ed25519_private_key
        self.hostname = hostname

        self.on_relay_message = on_relay_message  # callback(from_pubkey_hex, payload_dict)
        self.on_log = on_log

        self.conn = None
        self.send_lock = threading.Lock()
        self.connected = False

        ed25519_public_bytes = ed25519_private_key.public_key().public_bytes(
            encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.Raw,
            format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.Raw
        )
        self.my_pubkey_hex = ed25519_public_bytes.hex()

    def log(self, msg):
        self.on_log('info', f"[RelayClient] {msg}")

    def _send_framed(self, payload_dict):
        payload = json.dumps(payload_dict).encode()
        with self.send_lock:
            self.conn.sendall(len(payload).to_bytes(4, 'big'))
            self.conn.sendall(payload)

    def _recv_framed(self, timeout=None):
        if timeout:
            self.conn.settimeout(timeout)
        length_bytes = self._recv_exact(4)
        length = int.from_bytes(length_bytes, 'big')
        payload_bytes = self._recv_exact(length)
        return json.loads(payload_bytes.decode())

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connessione al server persa")
            buf += chunk
        return buf

    def connect_and_authenticate(self):
        """
        Stabilisce la connessione TCP col relay server e completa
        l'autenticazione challenge-response. Ritorna True/False.
        """
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.settimeout(10)
            self.conn.connect((self.server_host, self.server_port))

            self._send_framed({
                'type': 'hello',
                'pubkey': self.my_pubkey_hex,
                'hostname': self.hostname
            })

            challenge_msg = self._recv_framed(timeout=10)
            if challenge_msg.get('type') != 'challenge':
                self.log(f"Atteso 'challenge', ricevuto: {challenge_msg.get('type')}")
                return False

            challenge = base64.b64decode(challenge_msg['challenge'])
            signature = self.ed25519_private_key.sign(challenge)

            self._send_framed({
                'type': 'challenge_response',
                'signature': base64.b64encode(signature).decode()
            })

            result = self._recv_framed(timeout=10)
            if result.get('type') == 'auth_ok':
                self.connected = True
                self.log(f"Autenticato con successo sul relay server come '{self.hostname}'")
                return True
            else:
                self.log("Autenticazione rifiutata dal server")
                return False

        except (socket.timeout, ConnectionError, OSError) as e:
            self.log(f"Connessione al relay server fallita: {e}")
            return False

    def listen_loop(self):
        """
        Ciclo che riceve messaggi in arrivo dal server (relay in ingresso
        da altri nodi, o risposte a lookup). Va eseguito in un thread dedicato.
        """
        while self.connected:
            try:
                msg = self._recv_framed()
                msg_type = msg.get('type')

                if msg_type == 'incoming_relay':
                    from_pubkey = msg.get('from')
                    payload = msg.get('payload')
                    self.on_relay_message(from_pubkey, payload)

                elif msg_type == 'pong':
                    pass  # risposta a keepalive, nessuna azione necessaria

                elif msg_type == 'lookup_result':
                    # per ora gestito sincrono in lookup(), ma lasciamo il case
                    # per estensioni future (lookup asincroni)
                    pass

            except (ConnectionError, socket.timeout, json.JSONDecodeError) as e:
                self.log(f"Connessione al relay persa: {e}")
                self.connected = False
                break

    def lookup(self, target_pubkey_hex, timeout=5):
        """Chiede al server se un nodo (per chiave pubblica) è online. Chiamata sincrona."""
        try:
            self._send_framed({'type': 'lookup', 'pubkey': target_pubkey_hex})
            result = self._recv_framed(timeout=timeout)
            if result.get('type') == 'lookup_result':
                return result.get('online', False), result.get('hostname')
            return False, None
        except (ConnectionError, socket.timeout):
            return False, None

    def send_relay(self, target_pubkey_hex, payload_dict):
        """
        Manda un payload (già cifrato E2EE dal chiamante) al nodo target,
        tramite il relay server.
        """
        if not self.connected:
            self.log("Impossibile inviare: non connesso al relay server")
            return False
        try:
            self._send_framed({
                'type': 'relay',
                'to': target_pubkey_hex,
                'payload': payload_dict
            })
            return True
        except (ConnectionError, OSError) as e:
            self.log(f"Invio relay fallito: {e}")
            return False

    def keepalive_loop(self, interval=20):
        """Manda ping periodici per mantenere la connessione TCP attiva attraverso NAT/firewall intermedi."""
        while self.connected:
            time.sleep(interval)
            try:
                self._send_framed({'type': 'ping'})
            except (ConnectionError, OSError):
                self.connected = False
                break

    def start(self):
        """Avvia i thread di ascolto e keepalive dopo autenticazione riuscita."""
        threading.Thread(target=self.listen_loop, name="RelayListener", daemon=True).start()
        threading.Thread(target=self.keepalive_loop, name="RelayKeepalive", daemon=True).start()
