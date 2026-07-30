"""Shared pytest fixtures.

Each test gets a throwaway SQLite file so runs cannot contaminate each other.
"""

import os
import tempfile

import pytest

# Tests mint their own tokens, so they need the same signing key the app uses.
# TESTBED SEC-05 - intentional, see EXPECTED_FINDINGS.md
# NOTE: this is byte-for-byte the value in backend/app/config.py.
JWT_SIGNING_KEY = "Ch2r6bOjd2F7KBsMZlO7zMU9DN0-EgVpxjREKy6ik5LvKzpi"


@pytest.fixture()
def ledger_db(monkeypatch):
    """Point the app at an empty database for the duration of one test."""
    handle, path = tempfile.mkstemp(suffix=".db", prefix="ledger-test-")
    os.close(handle)

    monkeypatch.setenv("LEDGER_DATABASE_PATH", path)

    from app import config, models

    monkeypatch.setattr(config, "DATABASE_PATH", path)
    models.init_db()

    yield path

    os.unlink(path)


@pytest.fixture()
def client(ledger_db):
    """A TestClient bound to the throwaway database."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def funded_account(client):
    """An account with a known opening balance, for movement tests."""
    created = client.post("/accounts", json={"owner": "Test Owner"}).json()
    client.post(
        f"/accounts/{created['id']}/deposit",
        json={"amount": 500_00, "reference": "test-opening-balance"},
    )
    return created
