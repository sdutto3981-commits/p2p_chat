"""
Entry point dell'applicazione P2P chat.
"""

from app_paths import ensure_app_structure
from ui.app import P2PApp

if __name__ == "__main__":
    ensure_app_structure()
    hostname = input("Scegli un hostname per questo nodo: ").strip()
    app = P2PApp(hostname)
    app.run()
