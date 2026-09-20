"""
Gestione dell'identità persistente del nodo: genera, salva (cifrata con
passphrase) e ricarica DUE coppie di chiavi:
- X25519: per lo scambio chiavi nelle sessioni P2P dirette (già in uso)
- Ed25519: per l'autenticazione challenge-response col Rendezvous Server

Teoria:
- Nessuna chiave privata tocca MAI il disco in chiaro.
- La passphrase utente viene trasformata in chiave di cifratura tramite
  PBKDF2-HMAC-SHA256 con salt casuale e iterazioni alte.
- Le due chiavi private vengono cifrate insieme con AES-GCM e salvate
  in un unico file.
"""

import os
import json
import base64
import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app_paths import APP_ROOT, ensure_app_structure

IDENTITY_FILE = os.path.join(APP_ROOT, "identity.json")

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12


def _derive_key_from_passphrase(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def identity_exists():
    return os.path.isfile(IDENTITY_FILE)


def create_identity(passphrase):
    """
    Genera X25519 (sessioni P2P) + Ed25519 (autenticazione server),
    le cifra insieme e le salva su disco.
    Ritorna (x25519_private_key, ed25519_private_key).
    """
    ensure_app_structure()

    x25519_private = X25519PrivateKey.generate()
    x25519_bytes = x25519_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    ed25519_private = Ed25519PrivateKey.generate()
    ed25519_bytes = ed25519_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    # X25519 e Ed25519 raw sono entrambe 32 byte, ma salviamo comunque
    # la lunghezza esplicitamente per robustezza futura
    combined_bytes = len(x25519_bytes).to_bytes(1, 'big') + x25519_bytes + ed25519_bytes

    salt = os.urandom(SALT_SIZE)
    enc_key = _derive_key_from_passphrase(passphrase, salt)

    aesgcm = AESGCM(enc_key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, combined_bytes, None)

    data = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'kdf_iterations': PBKDF2_ITERATIONS,
    }

    with open(IDENTITY_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    return x25519_private, ed25519_private


def load_identity(passphrase):
    """
    Decifra e ritorna (x25519_private_key, ed25519_private_key).
    Solleva ValueError se la passphrase è sbagliata.
    """
    if not identity_exists():
        raise FileNotFoundError("Nessuna identità salvata trovata")

    with open(IDENTITY_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)

    salt = base64.b64decode(data['salt'])
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    iterations_used = data.get('kdf_iterations', PBKDF2_ITERATIONS)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations_used,
    )
    enc_key = kdf.derive(passphrase.encode('utf-8'))

    aesgcm = AESGCM(enc_key)
    try:
        combined_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Passphrase errata o file identità corrotto")

    x25519_len = combined_bytes[0]
    x25519_bytes = combined_bytes[1:1 + x25519_len]
    ed25519_bytes = combined_bytes[1 + x25519_len:]

    x25519_private = X25519PrivateKey.from_private_bytes(x25519_bytes)
    ed25519_private = Ed25519PrivateKey.from_private_bytes(ed25519_bytes)

    return x25519_private, ed25519_private


def get_or_create_identity():
    """
    Punto di ingresso principale. Ritorna sempre una tupla
    (x25519_private_key, ed25519_private_key).
    """
    if identity_exists():
        print("Identità esistente trovata.")
        for attempt in range(3):
            passphrase = getpass.getpass("Inserisci la passphrase: ")
            try:
                return load_identity(passphrase)
            except ValueError:
                print(f"Passphrase errata. Tentativi rimasti: {2 - attempt}")
        raise SystemExit("Troppi tentativi falliti. Uscita.")
    else:
        print("Nessuna identità trovata. Creiamone una nuova.")
        print("Questa passphrase proteggerà la tua identità sui prossimi avvii.")
        print("IMPORTANTE: se la perdi, non potrai più recuperare questa identità.")

        while True:
            passphrase = getpass.getpass("Scegli una passphrase: ")
            confirm = getpass.getpass("Conferma passphrase: ")
            if passphrase != confirm:
                print("Le passphrase non combaciano, riprova.")
                continue
            if len(passphrase) < 8:
                print("Usa almeno 8 caratteri.")
                continue
            break

        x25519_private, ed25519_private = create_identity(passphrase)
        print(f"Identità creata e salvata in {IDENTITY_FILE}")
        return x25519_private, ed25519_private
