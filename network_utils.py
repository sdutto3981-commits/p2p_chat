"""
Utility di rete di basso livello: rilevamento indirizzo di broadcast,
lettura esatta di N byte da un socket TCP (necessaria perché TCP
può frammentare un payload in più pacchetti fisici).
"""

import platform
import subprocess
import re


def get_broadcast_address(fallback='255.255.255.255'):
    """
    Calcola l'indirizzo di broadcast della subnet locale.
    Più affidabile del broadcast globale su alcune configurazioni di rete.
    """
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
    """
    Legge esattamente n byte da un socket TCP.
    TCP è un protocollo a stream: un singolo .recv() non garantisce
    di ricevere tutti i byte attesi in un colpo solo, va ciclato.
    """
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connessione chiusa prematuramente durante la lettura")
        buf += chunk
    return buf
