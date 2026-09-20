"""
Registro persistente dei contatti "remoti" (fuori LAN, raggiungibili
solo via relay), identificati dalla loro chiave pubblica Ed25519.
Diverso dal discovery LAN, che è sempre "a caldo" via broadcast e non
richiede persistenza.
"""

import json
import os
import threading

from app_paths import APP_ROOT, ensure_app_structure

CONTACTS_FILE = os.path.join(APP_ROOT, "contacts.json")


class ContactsStore:
    def __init__(self):
        ensure_app_structure()
        self.lock = threading.Lock()
        self.contacts = self._load()  # ed25519_pub_hex -> {hostname, x25519_pub_hex}

    def _load(self):
        if not os.path.isfile(CONTACTS_FILE):
            return {}
        try:
            with open(CONTACTS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save(self):
        with open(CONTACTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.contacts, f, indent=2, ensure_ascii=False)

    def add_contact(self, hostname, ed25519_pub_hex, x25519_pub_hex):
        with self.lock:
            self.contacts[ed25519_pub_hex] = {
                'hostname': hostname,
                'x25519_pub_hex': x25519_pub_hex,
            }
            self._save()

    def get_by_hostname(self, hostname):
        """Ritorna (ed25519_pub_hex, x25519_pub_hex) o (None, None) se non trovato."""
        with self.lock:
            for pubkey_hex, info in self.contacts.items():
                if info['hostname'] == hostname:
                    return pubkey_hex, info['x25519_pub_hex']
        return None, None

    def get_all(self):
        with self.lock:
            return dict(self.contacts)
