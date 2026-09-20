"""
Client STUN minimale (RFC 5389) per scoprire il proprio IP:porta pubblici
visti dall'esterno, attraverso il NAT del router.

Non usa librerie esterne: il protocollo STUN base è semplice abbastanza
da implementarlo direttamente sopra un socket UDP.
"""

import socket
import struct
import os

# Server STUN pubblici gratuiti (Google ne mantiene diversi, sempre attivi)
STUN_SERVERS = [
    ('stun.l.google.com', 19302),
    ('stun1.l.google.com', 19302),
    ('stun.stunprotocol.org', 3478),
]

STUN_MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
MAPPED_ADDRESS = 0x0001
XOR_MAPPED_ADDRESS = 0x0020  # versione moderna, preferita da server STUN recenti


def _build_binding_request():
    """
    Costruisce un pacchetto STUN Binding Request.
    Formato header (20 byte totali):
    - 2 byte: tipo messaggio (0x0001 = Binding Request)
    - 2 byte: lunghezza del body (0 per una richiesta base, nessun attributo)
    - 4 byte: magic cookie (valore fisso definito dalla RFC)
    - 12 byte: transaction ID (casuale, per abbinare richiesta e risposta)
    """
    transaction_id = os.urandom(12)
    header = struct.pack('>HHI', BINDING_REQUEST, 0, STUN_MAGIC_COOKIE) + transaction_id
    return header, transaction_id


def _parse_binding_response(data, expected_transaction_id):
    """
    Estrae IP:porta pubblici dalla risposta del server STUN.
    Cerca l'attributo XOR-MAPPED-ADDRESS (moderno) o MAPPED-ADDRESS (legacy).
    """
    if len(data) < 20:
        raise ValueError("Risposta STUN troppo corta")

    msg_type, msg_len, magic_cookie = struct.unpack('>HHI', data[:8])
    transaction_id = data[8:20]

    if msg_type != BINDING_RESPONSE:
        raise ValueError(f"Tipo messaggio inatteso: {msg_type:#x}")
    if transaction_id != expected_transaction_id:
        raise ValueError("Transaction ID non combacia (risposta non pertinente)")

    # scorri gli attributi TLV nel body
    offset = 20
    body_end = 20 + msg_len

    while offset < body_end:
        attr_type, attr_len = struct.unpack('>HH', data[offset:offset + 4])
        attr_value = data[offset + 4:offset + 4 + attr_len]

        if attr_type == XOR_MAPPED_ADDRESS:
            return _decode_xor_mapped_address(attr_value, transaction_id)
        elif attr_type == MAPPED_ADDRESS:
            return _decode_mapped_address(attr_value)

        # gli attributi sono allineati a 4 byte (padding se necessario)
        offset += 4 + attr_len + (attr_len % 4)

    raise ValueError("Nessun attributo di indirizzo trovato nella risposta")


def _decode_xor_mapped_address(value, transaction_id):
    """
    XOR-MAPPED-ADDRESS ha l'indirizzo mascherato in XOR con il magic cookie
    (e transaction ID per IPv6), per evitare che alcuni middlebox di rete
    lo riscrivano per errore pensando sia un indirizzo IP normale nel payload.
    """
    family = value[1]
    if family != 0x01:  # 0x01 = IPv4, 0x02 = IPv6 (non gestito qui per semplicità)
        raise ValueError("Solo IPv4 supportato in questo client")

    xor_port = struct.unpack('>H', value[2:4])[0]
    port = xor_port ^ (STUN_MAGIC_COOKIE >> 16)

    xor_ip = struct.unpack('>I', value[4:8])[0]
    ip_int = xor_ip ^ STUN_MAGIC_COOKIE
    ip = socket.inet_ntoa(struct.pack('>I', ip_int))

    return ip, port


def _decode_mapped_address(value):
    """Formato legacy, senza mascheramento XOR."""
    family = value[1]
    if family != 0x01:
        raise ValueError("Solo IPv4 supportato in questo client")

    port = struct.unpack('>H', value[2:4])[0]
    ip = socket.inet_ntoa(value[4:8])
    return ip, port


def get_public_address(local_port=0, timeout=3):
    """
    Interroga i server STUN in sequenza finché uno risponde.
    local_port: se specificato, il socket viene bindato a quella porta locale
                (utile per far coincidere la porta usata poi per il vero
                traffico P2P, importante per l'hole punching nella Fase 3).
    Ritorna (ip_pubblico, porta_pubblica) o solleva un'eccezione se tutti i server falliscono.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind(('0.0.0.0', local_port))

    last_error = None
    for server_host, server_port in STUN_SERVERS:
        try:
            request, transaction_id = _build_binding_request()
            sock.sendto(request, (server_host, server_port))

            data, _addr = sock.recvfrom(2048)
            public_ip, public_port = _parse_binding_response(data, transaction_id)

            sock.close()
            return public_ip, public_port

        except (socket.timeout, OSError, ValueError) as e:
            last_error = e
            continue

    sock.close()
    raise ConnectionError(f"Tutti i server STUN hanno fallito. Ultimo errore: {last_error}")


if __name__ == "__main__":
    print("Interrogazione server STUN in corso...")
    try:
        ip, port = get_public_address()
        print(f"\nIl tuo IP pubblico: {ip}")
        print(f"Porta pubblica mappata dal NAT: {port}")
        print(f"\n(Nota: la porta cambia ad ogni esecuzione se il NAT non è 'cone' — è normale)")
    except ConnectionError as e:
        print(f"Errore: {e}")
