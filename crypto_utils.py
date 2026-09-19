"""
Funzioni crittografiche: scambio chiavi X25519, derivazione chiave
simmetrica via HKDF, cifratura/decifratura AES-GCM.
Nessuna logica di rete qui dentro — solo primitive crittografiche pure.
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


HKDF_INFO = b'p2p-handshake-v1'


def generate_keypair():
    """Genera una nuova coppia di chiavi X25519 (privata, pubblica)."""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def pubkey_to_bytes(public_key):
    """Serializza una chiave pubblica X25519 in bytes raw (32 byte)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def derive_shared_key(private_key, their_pubkey_bytes):
    """
    Esegue ECDH (X25519) con la chiave privata locale e la chiave
    pubblica del peer, poi deriva una chiave simmetrica a 256 bit via HKDF-SHA256.
    """
    their_pubkey = X25519PublicKey.from_public_bytes(their_pubkey_bytes)
    shared_secret = private_key.exchange(their_pubkey)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO
    ).derive(shared_secret)


def encrypt(shared_key, plaintext_bytes):
    """Cifra con AES-GCM. Ritorna (nonce, ciphertext)."""
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def decrypt(shared_key, nonce, ciphertext):
    """Decifra con AES-GCM. Solleva InvalidTag se autenticazione fallisce."""
    aesgcm = AESGCM(shared_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
