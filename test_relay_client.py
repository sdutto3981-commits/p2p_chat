from identity import get_or_create_identity
from relay_client import RelayClient

RELAY_HOST = "p2p-relay-stefano.fly.dev"  # sostituisci con il tuo hostname Fly.io
RELAY_PORT = 8443


def on_relay_message(from_pubkey, payload):
    print(f"Messaggio relay ricevuto da {from_pubkey[:16]}...: {payload}")


def on_log(level, msg):
    print(f"[{level}] {msg}")


if __name__ == "__main__":
    x25519_key, ed25519_key = get_or_create_identity()

    client = RelayClient(
        RELAY_HOST, RELAY_PORT,
        x25519_key, ed25519_key,
        hostname="test-nodo",
        on_relay_message=on_relay_message,
        on_log=on_log
    )

    if client.connect_and_authenticate():
        client.start()
        print(f"\nLa mia chiave pubblica Ed25519: {client.my_pubkey_hex}")
        print("Connesso. Premi Ctrl+C per uscire.\n")

        import time
        while True:
            time.sleep(1)
    else:
        print("Autenticazione fallita.")
