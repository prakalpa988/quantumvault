"""Create and seed the QuantumVault SQLite transaction database."""

from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import oqs
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


DATABASE_PATH = Path(__file__).with_name("transactions.db")
TRANSACTION_COUNT = 20
RSA_COUNT = 12


def encode(value: bytes) -> str:
    """Store binary cryptographic material safely in a text column."""
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
            signature TEXT NOT NULL
        )
        """
    )


def rsa_transaction(message: bytes) -> tuple[str, str, str]:
    key = RSA.generate(2048)

    signature = pkcs1_15.new(key).sign(
        SHA256.new(message)
    )

    return (
        "RSA-2048",
        key.publickey().export_key(
            format="PEM"
        ).decode("ascii"),
        encode(signature),
    )


def mldsa_transaction(message: bytes) -> tuple[str, str, str]:
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)

    return (
        "ML-DSA-65",
        encode(public_key),
        encode(signature),
    )


def seed_database() -> None:
    with sqlite3.connect(DATABASE_PATH) as connection:
        create_schema(connection)

        for transaction_id in range(
            1,
            TRANSACTION_COUNT + 1,
        ):
            sender = f"wallet-{transaction_id:02d}"

            receiver = (
                f"vault-{((transaction_id + 3) % TRANSACTION_COUNT) + 1:02d}"
            )

            amount = round(
                125.50 + (transaction_id * 73.25),
                2,
            )

            message = (
                f"{transaction_id}|"
                f"{sender}|"
                f"{receiver}|"
                f"{amount:.2f}"
            ).encode()

            if transaction_id <= RSA_COUNT:
                (
                    algorithm,
                    public_key,
                    signature,
                ) = rsa_transaction(message)
            else:
                (
                    algorithm,
                    public_key,
                    signature,
                ) = mldsa_transaction(message)

            connection.execute(
                """
                INSERT INTO transactions (
                    id,
                    sender,
                    receiver,
                    amount,
                    crypto_algorithm,
                    public_key,
                    signature
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transaction_id,
                    sender,
                    receiver,
                    amount,
                    algorithm,
                    public_key,
                    signature,
                ),
            )

        connection.commit()

    print(
        f"Seeded {TRANSACTION_COUNT} transactions "
        f"into {DATABASE_PATH}"
    )


if __name__ == "__main__":
    seed_database()
