"""
Storage Server — untrusted, honest-but-curious blob store.

Threat model
------------
The server is operated by a third party who:
  * Faithfully stores and serves every encrypted package it receives.
  * Will inspect stored bytes if it can.

Security guarantee
------------------
The server never receives any key material (PK, MK, or any user SK).
Every file is encrypted before it arrives.  The server therefore sees:
  * Encrypted package bytes  — reveals nothing about file content.
  * The access policy string — embedded in the package in plaintext.
    In a higher-security design this would be hidden (hidden-policy
    CP-ABE), but that is out of scope for this project.
  * Ciphertext length        — reveals approximate file size.
  * Upload/download timing   — traffic analysis is out of scope.

Even if the server is fully compromised (filesystem dump, memory dump),
an attacker learns nothing about the file contents.

API
---
POST   /upload/{file_id}        — store an encrypted package blob
GET    /download/{file_id}      — retrieve a blob
GET    /files                   — list stored file IDs and sizes
DELETE /files/{file_id}         — remove a file
GET    /health                  — liveness probe (used by docker-compose)
"""

import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import FileResponse

STORAGE_DIR = Path(os.environ.get("STORAGE_DIR", "storage"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="CP-ABE Secure File Storage",
    description="Untrusted blob store — holds encrypted packages only.",
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/upload/{file_id}", status_code=201)
async def upload(file_id: str, file: UploadFile):
    """
    Store an encrypted package under the given file_id.

    The file_id is chosen by the uploader (typically the original filename
    or a UUID).  Uploading twice with the same file_id overwrites the old blob.
    """
    _validate_file_id(file_id)
    dest = STORAGE_DIR / file_id
    dest.write_bytes(await file.read())
    return {"file_id": file_id, "size_bytes": dest.stat().st_size}


@app.get("/download/{file_id}")
def download(file_id: str):
    """Return the encrypted package bytes for the given file_id."""
    _validate_file_id(file_id)
    path = STORAGE_DIR / file_id
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File '{file_id}' not found.")
    return FileResponse(path, media_type="application/octet-stream", filename=file_id)


@app.get("/files")
def list_files():
    """Return a list of all stored file IDs and their sizes."""
    return {
        "files": [
            {"file_id": f.name, "size_bytes": f.stat().st_size}
            for f in sorted(STORAGE_DIR.iterdir())
            if f.is_file()
        ]
    }


@app.delete("/files/{file_id}", status_code=200)
def delete_file(file_id: str):
    """Remove a stored file."""
    _validate_file_id(file_id)
    path = STORAGE_DIR / file_id
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"File '{file_id}' not found.")
    path.unlink()
    return {"deleted": file_id}


def _validate_file_id(file_id: str) -> None:
    """Reject path traversal attempts (e.g. '../secrets')."""
    if "/" in file_id or "\\" in file_id or file_id.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid file_id.")


if __name__ == "__main__":
    uvicorn.run(
        "storage_server.server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )
