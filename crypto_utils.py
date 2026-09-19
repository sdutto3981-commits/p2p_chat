"""
Funzioni crittografiche: scambio chiavi X25519, derivazione chiave
simmetrica via HKDF, cifratura/decifratura AES-GCM.
"""

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

HKDF_INFO = b'p2p-handshake-v1'


def generate_keypair():
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def pubkey_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def derive_shared_key(private_key, their_pubkey_bytes):
    their_pubkey = X25519PublicKey.from_public_bytes(their_pubkey_bytes)
    shared_secret = private_key.exchange(their_pubkey)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO
    ).derive(shared_secret)


def encrypt(shared_key, plaintext_bytes):
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def decrypt(shared_key, nonce, ciphertext):
    aesgcm = AESGCM(shared_key)
    return aesgcm.decrypt(nonce, ciphertext, None)
