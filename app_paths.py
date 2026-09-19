"""
Punto unico di definizione della struttura cartelle dell'applicazione.
"""

import os

APP_ROOT = os.path.join(os.path.expanduser("~"), "P2PChat")
LOGS_DIR = os.path.join(APP_ROOT, "logs")
RECEIVED_DIR = os.path.join(APP_ROOT, "received")
TRANSFERS_LOG_FILE = os.path.join(APP_ROOT, "transfers.json")


def ensure_app_structure():
    os.makedirs(APP_ROOT, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    os.makedirs(RECEIVED_DIR, exist_ok=True)


def received_dir_for_peer(peer_hostname):
    path = os.path.join(RECEIVED_DIR, _sanitize_folder_name(peer_hostname))
    os.makedirs(path, exist_ok=True)
    return path


def _sanitize_folder_name(name):
    invalid = '<>:"/\\|?*'
    cleaned = ''.join(c for c in name if c not in invalid)
    return cleaned.strip() or "unknown_peer"
