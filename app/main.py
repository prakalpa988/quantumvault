"""QuantumVault FastAPI application."""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path
from typing import Any
import base64
import time
import oqs
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from fastapi import FastAPI, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

DATABASE_PATH = Path(__file__).with_name("transactions.db")
app = FastAPI(title="QuantumVault", version="1.0.0")

# Serve dashboard static assets if present
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def get_dashboard() -> HTMLResponse:
    """Serves the plain HTML dashboard root page."""
    html_path = os.path.join("static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r") as file:
            return HTMLResponse(content=file.read(), status_code=200)
    return HTMLResponse(content="<h1>Dashboard file missing</h1>", status_code=404)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/transactions")
def list_transactions() -> list[dict[str, Any]]:
    """Returns all transactions from the database, real crypto included."""
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, sender, receiver, amount, crypto_algorithm, public_key, signature
            FROM transactions
            ORDER BY id
            """
        ).fetchall()
    return [dict(row) for row in rows]


VULNERABLE_ALGOS = {"RSA-2048", "RSA-4096", "ECDSA"}


@app.get("/audit")
def audit_transactions() -> dict[str, Any]:
    """Scans transactions and flags which ones use quantum-vulnerable crypto."""
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, amount, crypto_algorithm FROM transactions ORDER BY id"
        ).fetchall()

    results = [
        {
            "id": row["id"],
            "amount": row["amount"],
            "algorithm": row["crypto_algorithm"],
            "vulnerable": row["crypto_algorithm"] in VULNERABLE_ALGOS,
        }
        for row in rows
    ]
    return {
        "total": len(results),
        "vulnerable_count": sum(1 for r in results if r["vulnerable"]),
        "transactions": results,
    }
@app.post("/migrate/{tx_id}")
def migrate_transaction(tx_id: int) -> dict[str, Any]:
    """Re-signs a single RSA transaction with ML-DSA-65, replacing its signature."""
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT id, sender, receiver, amount, crypto_algorithm FROM transactions WHERE id = ?",
            (tx_id,),
        ).fetchone()

        if row is None:
            return {"error": f"Transaction {tx_id} not found"}

        if row["crypto_algorithm"] == "ML-DSA-65":
            return {"id": tx_id, "status": "already migrated", "algorithm": "ML-DSA-65"}

        message = f"{row['id']}|{row['sender']}|{row['receiver']}|{row['amount']:.2f}".encode()

        with oqs.Signature("ML-DSA-65") as signer:
            public_key = signer.generate_keypair()
            signature = signer.sign(message)

        connection.execute(
            "UPDATE transactions SET crypto_algorithm = ?, public_key = ?, signature = ? WHERE id = ?",
            (
                "ML-DSA-65",
                base64.b64encode(public_key).decode("ascii"),
                base64.b64encode(signature).decode("ascii"),
                tx_id,
            ),
        )
        connection.commit()

    return {"id": tx_id, "migrated_to": "ML-DSA-65", "status": "success"}


@app.get("/benchmark")
def benchmark_algorithms() -> dict[str, Any]:
    """Times real ML-KEM-768 and ML-DSA-65 operations against an RSA-2048 baseline."""
    results: dict[str, Any] = {}

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        t0 = time.perf_counter()
        pub = kem.generate_keypair()
        t1 = time.perf_counter()
        ciphertext, shared_secret = kem.encap_secret(pub)
        t2 = time.perf_counter()
    results["ML-KEM-768"] = {
        "keygen_ms": round((t1 - t0) * 1000, 3),
        "encapsulate_ms": round((t2 - t1) * 1000, 3),
        "public_key_bytes": len(pub),
        "ciphertext_bytes": len(ciphertext),
    }

    with oqs.Signature("ML-DSA-65") as signer:
        t0 = time.perf_counter()
        pub = signer.generate_keypair()
        t1 = time.perf_counter()
        sig = signer.sign(b"benchmark message")
        t2 = time.perf_counter()
    results["ML-DSA-65"] = {
        "keygen_ms": round((t1 - t0) * 1000, 3),
        "sign_ms": round((t2 - t1) * 1000, 3),
        "public_key_bytes": len(pub),
        "signature_bytes": len(sig),
    }

    t0 = time.perf_counter()
    key = RSA.generate(2048)
    t1 = time.perf_counter()
    h = SHA256.new(b"benchmark message")
    sig = pkcs1_15.new(key).sign(h)
    t2 = time.perf_counter()
    results["RSA-2048"] = {
        "keygen_ms": round((t1 - t0) * 1000, 3),
        "sign_ms": round((t2 - t1) * 1000, 3),
        "public_key_bytes": len(key.publickey().export_key()),
        "signature_bytes": len(sig),
    }

    return results


@app.get("/api/attack-demo")
def attack_demo() -> dict[str, str]:
    """Illustrative explanation only — no real cryptanalysis is performed."""
    return {
        "disclaimer": "Illustrative explanation only. No real attack is executed.",
        "rsa_risk": (
            "RSA and ECDSA rely on integer factorization and discrete logarithms, "
            "both of which Shor's algorithm solves in polynomial time on a "
            "sufficiently large, fault-tolerant quantum computer."
        ),
        "mldsa_resistance": (
            "ML-DSA and ML-KEM rely on the hardness of lattice problems "
            "(Module-LWE / Module-SIS), for which no efficient quantum algorithm "
            "is currently known, making them NIST-standardized post-quantum choices."
        ),
    }
    
