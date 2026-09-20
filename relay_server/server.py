"""
Rendezvous + Relay Server.

Compiti:
1. Autentica i nodi tramite challenge-response Ed25519 (dimostrano di
   possedere la chiave privata senza mai rivelarla).
2. Tiene una tabella chiave_pubblica -> connessione attiva.
3. Inoltra pacchetti cifrati tra nodi (relay cieco: non vede mai il
   contenuto in chiaro, solo bytes già cifrati E2EE lato client).

Protocollo sopra TCP, messaggi length-prefixed (4 byte big-endian di
lunghezza, poi il payload JSON).
"""

import socket
import threading
import json
import base64
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

LISTEN_PORT = 8443
CHALLENGE_SIZE = 32
AUTH_TIMEOUT = 10  # secondi per completare l'autenticazione dopo la connessione


class RelayServer:
    def __init__(self):
        # chiave_pubblica_ed25519_hex -> { 'conn': socket, 'lock': threading.Lock() }
        self.nodes = {}
        self.nodes_lock = threading.Lock()

    def log(self, msg):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {msg}", flush=True)

    def send_framed(self, conn, payload_dict):
        """Invia un messaggio JSON con prefisso di lunghezza a 4 byte."""
        payload = json.dumps(payload_dict).encode()
        conn.sendall(len(payload).to_bytes(4, 'big'))
        conn.sendall(payload)

    def recv_framed(self, conn, timeout=None):
        """Riceve un messaggio JSON con prefisso di lunghezza a 4 byte."""
        if timeout:
            conn.settimeout(timeout)
        length_bytes = self._recv_exact(conn, 4)
        length = int.from_bytes(length_bytes, 'big')
        if length > 10 * 1024 * 1024:  # 10MB, limite di sicurezza contro payload malevoli enormi
            raise ValueError("Payload dichiarato troppo grande")
        payload_bytes = self._recv_exact(conn, length)
        return json.loads(payload_bytes.decode())

    def _recv_exact(self, conn, n):
        buf = b''
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connessione chiusa durante la lettura")
            buf += chunk
        return buf

    def authenticate(self, conn, addr):
        """
        Flusso di autenticazione:
        1. Il client dichiara la sua chiave pubblica Ed25519 e il suo hostname scelto
        2. Il server genera un challenge casuale e lo manda
        3. Il client firma il challenge con la sua chiave privata Ed25519 e rimanda la firma
        4. Il server verifica la firma con la chiave pubblica dichiarata

        Ritorna (pubkey_hex, hostname) se autenticato con successo, altrimenti None.
        """
        try:
            hello = self.recv_framed(conn, timeout=AUTH_TIMEOUT)
            if hello.get('type') != 'hello':
                self.log(f"[{addr}] Messaggio iniziale non valido")
                return None

            pubkey_hex = hello.get('pubkey')
            hostname = hello.get('hostname')
            if not pubkey_hex or not hostname:
                self.log(f"[{addr}] hello incompleto")
                return None

            try:
                pubkey_bytes = bytes.fromhex(pubkey_hex)
                public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            except Exception:
                self.log(f"[{addr}] Chiave pubblica non valida")
                return None

            challenge = os.urandom(CHALLENGE_SIZE)
            self.send_framed(conn, {
                'type': 'challenge',
                'challenge': base64.b64encode(challenge).decode()
            })

            response = self.recv_framed(conn, timeout=AUTH_TIMEOUT)
            if response.get('type') != 'challenge_response':
                self.log(f"[{addr}] Risposta al challenge mancante")
                return None

            signature = base64.b64decode(response.get('signature', ''))

            try:
                public_key.verify(signature, challenge)
            except InvalidSignature:
                self.log(f"[{addr}] Firma non valida — autenticazione fallita")
                self.send_framed(conn, {'type': 'auth_failed'})
                return None

            self.send_framed(conn, {'type': 'auth_ok'})
            self.log(f"[{addr}] Autenticato: hostname='{hostname}' pubkey={pubkey_hex[:16]}...")
            return pubkey_hex, hostname

        except (socket.timeout, ConnectionError, json.JSONDecodeError, ValueError) as e:
            self.log(f"[{addr}] Autenticazione fallita: {e}")
            return None

    def handle_client(self, conn, addr):
        auth_result = self.authenticate(conn, addr)
        if not auth_result:
            conn.close()
            return

        pubkey_hex, hostname = auth_result

        with self.nodes_lock:
            self.nodes[pubkey_hex] = {'conn': conn, 'hostname': hostname, 'lock': threading.Lock()}

        try:
            while True:
                msg = self.recv_framed(conn)
                msg_type = msg.get('type')

                if msg_type == 'lookup':
                    self._handle_lookup(conn, msg)
                elif msg_type == 'relay':
                    self._handle_relay(pubkey_hex, msg)
                elif msg_type == 'ping':
                    self.send_framed(conn, {'type': 'pong'})
                else:
                    self.log(f"[{addr}] Tipo messaggio sconosciuto: {msg_type}")

        except (ConnectionError, socket.timeout, json.JSONDecodeError):
            pass
        finally:
            with self.nodes_lock:
                if pubkey_hex in self.nodes:
                    del self.nodes[pubkey_hex]
            self.log(f"[{addr}] Nodo '{hostname}' disconnesso")
            conn.close()

    def _handle_lookup(self, conn, msg):
        """Un nodo chiede se un altro (per chiave pubblica) è online."""
        target_pubkey = msg.get('pubkey')
        with self.nodes_lock:
            online = target_pubkey in self.nodes
            hostname = self.nodes[target_pubkey]['hostname'] if online else None
        self.send_framed(conn, {'type': 'lookup_result', 'online': online, 'hostname': hostname})

    def _handle_relay(self, sender_pubkey, msg):
        """
        Inoltra un pacchetto (già cifrato E2EE dal mittente) al nodo destinatario,
        se online. Il server non decifra né ispeziona il contenuto.
        """
        target_pubkey = msg.get('to')
        inner_payload = msg.get('payload')  # bytes cifrati lato applicativo, opachi qui

        with self.nodes_lock:
            target = self.nodes.get(target_pubkey)

        if not target:
            self.log(f"Relay fallito: destinatario {target_pubkey[:16]}... non online")
            return

        forward_msg = {
            'type': 'incoming_relay',
            'from': sender_pubkey,
            'payload': inner_payload
        }

        try:
            with target['lock']:
                self.send_framed(target['conn'], forward_msg)
        except (ConnectionError, OSError) as e:
            self.log(f"Relay fallito verso {target_pubkey[:16]}...: {e}")

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('0.0.0.0', LISTEN_PORT))
        srv.listen(20)
        self.log(f"Relay server in ascolto su porta {LISTEN_PORT}")

        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    server = RelayServer()
    server.start()