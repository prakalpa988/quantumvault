from fastapi import FastAPI, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI(title="PQC Secured Dashboard")

# Look for static assets inside the app/static folder
if os.path.exists("app/static"):
    app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the plain HTML dashboard root page."""
    html_path = os.path.join("app", "static", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r") as file:
            return HTMLResponse(content=file.read(), status_code=200)
    return HTMLResponse(content="<h1>Dashboard file missing</h1>", status_code=404)

@app.post("/api/pqc/keygen", status_code=status.HTTP_200_OK)
async def get_quantum_keys():
    """Placeholder API endpoint for post-quantum key generation."""
    return {"status": "ready", "algorithm": "ML-KEM-768"}
