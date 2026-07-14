"""Application entrypoint.

Run with:  uvicorn app.main:app --reload   (from the backend/ directory)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import api, config, models


@asynccontextmanager
async def lifespan(app: FastAPI):
    models.init_db()
    yield


app = FastAPI(
    title="ARVE Ledger Testbed",
    description=(
        "Minimal double-entry payments ledger. "
        "INTENTIONALLY VULNERABLE — see README.md. Do not deploy."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# The operator console is served as a static page from a different origin
# during development, so it needs to be allowed through.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api.router)


@app.get("/health")
def health():
    return {"status": "ok", "provider": config.PROVIDER_NAME}
