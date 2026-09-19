"""
Registro persistente dei messaggi testuali scambiati, per peer.
"""

import json
import os
import threading
from datetime import datetime

from app_paths import APP_ROOT, ensure_app_structure

MESSAGES_LOG_FILE = os.path.join(APP_ROOT, "messages.json")


class MessageLog:
    def __init__(self):
        ensure_app_structure()
        self.lock = threading.Lock()
        self.entries = self._load()

    def _load(self):
        if not os.path.isfile(MESSAGES_LOG_FILE):
            return []
        try:
            with open(MESSAGES_LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self):
        with open(MESSAGES_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.entries, f, indent=2, ensure_ascii=False)

    def add_entry(self, direction, peer, text):
        entry = {
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'direction': direction,
            'peer': peer,
            'text': text,
        }
        with self.lock:
            self.entries.append(entry)
            self._save()
        return entry

    def get_by_peer(self, peer):
        with self.lock:
            return [e for e in self.entries if e['peer'] == peer]
