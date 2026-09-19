"""
Registro persistente dei file/media inviati e ricevuti.
"""

import json
import os
import threading
from datetime import datetime

from app_paths import TRANSFERS_LOG_FILE, ensure_app_structure


class TransferLog:
    def __init__(self):
        ensure_app_structure()
        self.lock = threading.Lock()
        self.entries = self._load()

    def _load(self):
        if not os.path.isfile(TRANSFERS_LOG_FILE):
            return []
        try:
            with open(TRANSFERS_LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def _save(self):
        with open(TRANSFERS_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.entries, f, indent=2, ensure_ascii=False)

    def add_entry(self, direction, peer, filename, filepath, filesize):
        entry = {
            'timestamp': datetime.now().isoformat(timespec='seconds'),
            'direction': direction,
            'peer': peer,
            'filename': filename,
            'filepath': filepath,
            'filesize': filesize,
        }
        with self.lock:
            self.entries.append(entry)
            self._save()
        return entry

    def get_all(self):
        with self.lock:
            return list(self.entries)

    def get_by_peer(self, peer):
        with self.lock:
            return [e for e in self.entries if e['peer'] == peer]
