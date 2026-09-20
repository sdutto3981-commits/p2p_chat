"""
Gestisce la creazione e il parsing delle "contact card": un codice
compatto che incapsula hostname + chiave pubblica Ed25519 + chiave
pubblica X25519 di un nodo, da scambiarsi una tantum fuori dall'app
(messaggio, email, di persona) per potersi poi contattare via relay.

Formato: base64( JSON({hostname, ed25519_pub, x25519_pub}) )
con prefisso "P2PCARD:" per riconoscerlo a vista.
"""

import json
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization

CARD_PREFIX = "P2PCARD:"


def create_card(hostname, ed25519_private_key, x25519_private_key):
    """Genera la contact card di QUESTO nodo, da condividere con altri."""
    ed25519_pub_bytes = ed25519_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    x25519_pub_bytes = x25519_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    data = {
        'hostname': hostname,
        'ed25519_pub': ed25519_pub_bytes.hex(),
        'x25519_pub': x25519_pub_bytes.hex(),
    }

    json_bytes = json.dumps(data, separators=(',', ':')).encode('utf-8')
    encoded = base64.urlsafe_b64encode(json_bytes).decode('ascii')
    return CARD_PREFIX + encoded


def parse_card(card_string):
    """
    Decodifica una contact card ricevuta da un altro nodo.
    Ritorna un dict: {hostname, ed25519_pub_hex, x25519_pub_bytes, ed25519_pub_bytes}
    Solleva ValueError se il formato non è valido.
    """
    card_string = card_string.strip()
    if not card_string.startswith(CARD_PREFIX):
        raise ValueError("Formato contact card non riconosciuto (manca prefisso P2PCARD:)")

    encoded = card_string[len(CARD_PREFIX):]
    try:
        json_bytes = base64.urlsafe_b64decode(encoded)
        data = json.loads(json_bytes.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Contact card corrotta o malformata: {e}")

    required_fields = ('hostname', 'ed25519_pub', 'x25519_pub')
    if not all(f in data for f in required_fields):
        raise ValueError("Contact card incompleta (campi mancanti)")

    try:
        ed25519_pub_bytes = bytes.fromhex(data['ed25519_pub'])
        x25519_pub_bytes = bytes.fromhex(data['x25519_pub'])
        # verifica che siano chiavi valide, non solo hex a caso
        Ed25519PublicKey.from_public_bytes(ed25519_pub_bytes)
        X25519PublicKey.from_public_bytes(x25519_pub_bytes)
    except Exception as e:
        raise ValueError(f"Chiavi pubbliche non valide nella contact card: {e}")

    return {
        'hostname': data['hostname'],
        'ed25519_pub_hex': data['ed25519_pub'],
        'ed25519_pub_bytes': ed25519_pub_bytes,
        'x25519_pub_bytes': x25519_pub_bytes,
    }
