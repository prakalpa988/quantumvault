"""Create and seed the QuantumVault SQLite transaction database."""
from __future__ import annotations
import base64
import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import oqs
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15, DSS

DATABASE_PATH = Path(__file__).with_name("transactions.db")
TRANSACTION_COUNT = 20


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def create_schema(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TABLE IF EXISTS transactions")
    connection.execute(
        """
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            amount REAL NOT NULL,
            crypto_algorithm TEXT NOT NULL,
            public_key TEXT NOT NULL,
            signature TEXT NOT NULL,
            signed_at TEXT NOT NULL
        )
        """
    )


def rsa_transaction(message: bytes, bits: int = 2048) -> tuple[str, str, str]:
    key = RSA.generate(bits)
    signature = pkcs1_15.new(key).sign(SHA256.new(message))
    return (
        f"RSA-{bits}",
        key.publickey().export_key(format="PEM").decode("ascii"),
        encode(signature),
    )


def ecdsa_transaction(message: bytes) -> tuple[str, str, str]:
    key = ECC.generate(curve="P-256")
    signer = DSS.new(key, "fips-186-3")
    signature = signer.sign(SHA256.new(message))
    return (
        "ECDSA-P256",
        key.public_key().export_key(format="PEM"),
        encode(signature),
    )


def mldsa_transaction(message: bytes) -> tuple[str, str, str]:
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
    return ("ML-DSA-65", encode(public_key), encode(signature))


def random_wallet_id() -> str:
    return "0x" + "".join(random.choices("0123456789abcdef", k=10))


def random_timestamp() -> str:
    days_ago = random.randint(0, 45)
    seconds_ago = random.randint(0, 86400)
    ts = datetime.utcnow() - timedelta(days=days_ago, seconds=seconds_ago)
    return ts.isoformat(timespec="seconds") + "Z"


def seed_database() -> None:
    # 12 vulnerable transactions: mix of RSA-2048, RSA-4096, ECDSA-P256
    # 8 safe transactions: ML-DSA-65
    vulnerable_mix = (
        ["RSA-2048"] * 8 + ["RSA-4096"] * 2 + ["ECDSA-P256"] * 2
    )
    random.shuffle(vulnerable_mix)
    algorithm_plan = vulnerable_mix + ["ML-DSA-65"] * 8
    random.shuffle(algorithm_plan)

    with sqlite3.connect(DATABASE_PATH) as connection:
        create_schema(connection)

        for transaction_id, algo in enumerate(algorithm_plan, start=1):
            sender = random_wallet_id()
            receiver = random_wallet_id()
            amount = round(random.uniform(42.10, 18450.75), 2)
            signed_at = random_timestamp()

            message = f"{transaction_id}|{sender}|{receiver}|{amount:.2f}".encode()

            if algo == "RSA-2048":
                algorithm, public_key, signature = rsa_transaction(message, 2048)
            elif algo == "RSA-4096":
                algorithm, public_key, signature = rsa_transaction(message, 4096)
            elif algo == "ECDSA-P256":
                algorithm, public_key, signature = ecdsa_transaction(message)
            else:
                algorithm, public_key, signature = mldsa_transaction(message)

            connection.execute(
                """
                INSERT INTO transactions (
                    id, sender, receiver, amount,
                    crypto_algorithm, public_key, signature, signed_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (transaction_id, sender, receiver, amount, algorithm, public_key, signature, signed_at),
            )

        connection.commit()
    print(f"Seeded {TRANSACTION_COUNT} transactions into {DATABASE_PATH}")


if __name__ == "__main__":
    seed_database()
