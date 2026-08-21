"""QuantumVault FastAPI application."""
from __future__ import annotations
import os
import sqlite3
from pathlib import Path
from typing import Any

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
