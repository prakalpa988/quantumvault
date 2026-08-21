# quantumvault
# QuantumVault

QuantumVault is a FastAPI project backed by SQLite.
It stores sample transactions signed with:
- RSA-2048
- ML-DSA-65

## Project files
- `main.py` — FastAPI application
- `seed_db.py` — creates and seeds the database
- `transactions.db` — generated SQLite database (not committed, see below)
- `requirements.txt` — Python dependencies

## Install dependencies
```bash
python -m pip install -r requirements.txt
```

If `pyoqs` is unavailable, replace it in `requirements.txt` with `liboqs-python`, then reinstall.

## Create the database
```bash
python seed_db.py
```
This creates `transactions.db` with 20 transactions: 12 RSA-2048, 8 ML-DSA-65.

## Start the API
```bash
uvicorn main:app --reload
```

## Endpoints
- Health check: `http://127.0.0.1:8000/health`
- Transactions: `http://127.0.0.1:8000/transactions`
- Interactive docs: `http://127.0.0.1:8000/docs`
