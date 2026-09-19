"""
Utility di rete di basso livello.
"""

import platform
import subprocess
import re


def get_broadcast_address(fallback='255.255.255.255'):
    try:
        if platform.system() == "Windows":
            output = subprocess.run(['ipconfig'], capture_output=True, text=True).stdout
            ip_match = re.search(r'IPv4 Address[.\s]*: (\d+\.\d+\.\d+\.\d+)', output)
        else:
            output = subprocess.run(['ifconfig', 'en0'], capture_output=True, text=True).stdout
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)

        if ip_match:
            octets = ip_match.group(1).split('.')
            return '.'.join(octets[:3]) + '.255'
    except Exception:
        pass
    return fallback


def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connessione chiusa prematuramente durante la lettura")
        buf += chunk
    return buf
