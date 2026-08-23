"""
QuantumVault FastAPI application.

This is my backend for QuantumHacks 2026. I'm still fairly new to FastAPI —
picked it over Flask because the automatic /docs page was genuinely useful
while I was testing endpoints manually before I had a frontend at all.

Everything here reads from a SQLite file (transactions.db) that seed_db.py
generates. I kept the schema flat (one table) on purpose. A real system 
probably might split signatures into their own table, but for a hackathon
scope I didn't want to add relational complexity I didn't need to prove
the actual idea.
"""
from __future__ import annotations
import base64
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import oqs
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

DATABASE_PATH = Path(__file__).with_name("transactions.db")
app = FastAPI(title="QuantumVault", version="1.0.0")

# Serving the dashboard straight out of /static so I don't need a separate
# frontend build step — everything lives in one FastAPI process, which
# keeps the free-tier deploy simple.
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/", response_class=HTMLResponse)
async def get_dashboard() -> HTMLResponse:
    html_path = os.path.join("static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r") as file:
            return HTMLResponse(content=file.read(), status_code=200)
    # Fallback so the API doesn't just 500 if I forget to deploy the HTML —
    # learned this the hard way during an earlier Render deploy attempt.
    return HTMLResponse(content="<h1>Dashboard file missing</h1>", status_code=404)


@app.get("/health")
def health() -> dict[str, str]:
    """Basic uptime check — mostly useful for confirming Render actually woke the service up."""
    return {"status": "ok"}


@app.get("/transactions")
def list_transactions() -> list[dict[str, Any]]:
    """Raw dump of every transaction, keys and signatures included.

    I kept this separate from /audit on purpose — /audit is the "human readable"
    view for the dashboard, this one is closer to what you'd hit if you wanted
    to actually inspect the cryptographic material itself.
    """
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT id, sender, receiver, amount, crypto_algorithm, public_key, signature, signed_at
            FROM transactions
            ORDER BY id
            """
        ).fetchall()
    return [dict(row) for row in rows]


# These three are the algorithms I'm treating as "quantum-vulnerable" —
# all of them break under Shor's algorithm given a large enough quantum
# computer, since they rely on factoring or discrete log problems.
VULNERABLE_ALGOS = {"RSA-2048", "RSA-4096", "ECDSA-P256"}


@app.get("/audit")
def audit_transactions() -> dict[str, Any]:
    """Scans every transaction and flags which ones still use vulnerable crypto.

    This is the endpoint the dashboard actually calls first — I wanted the
    "how bad is it" number to be the very first thing the app tells you,
    before you can even look at individual transactions.
    """
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, sender, receiver, amount, crypto_algorithm, signed_at FROM transactions ORDER BY id"
        ).fetchall()

    results = [
        {
            "id": row["id"],
            "sender": row["sender"],
            "receiver": row["receiver"],
            "amount": row["amount"],
            "algorithm": row["crypto_algorithm"],
            "signed_at": row["signed_at"],
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
    """Re-signs one transaction with ML-DSA-65, replacing its old signature.

    Worth being clear about what this does NOT do: it doesn't touch the
    original transaction data (sender/receiver/amount), only the signature
    and public key. In a real system you'd probably want an audit trail of
    the old signature too, but I didn't build that — flagged as a known
    simplification, not something I forgot.
    """
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
    """Times real keygen/sign/encapsulate operations for each algorithm.

    I went back and forth on whether to run each of these multiple times
    and average them — decided against it for now since a single run is
    good enough to show the order-of-magnitude differences, which is really
    the point I'm trying to make (not sub-millisecond precision).
    """
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
    """Plain-language explainer — not a real attack simulation.

    Wanted to be upfront about this one: I'm not running Shor's algorithm
    or anything close to it. This just returns the reasoning in text, since
    actually simulating quantum cryptanalysis is way out of scope for what
    I could build in a hackathon (and honestly out of scope for a classical
    computer at all).
    """
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
        )
    }
