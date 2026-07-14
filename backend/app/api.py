"""HTTP routes.

Seven endpoints, no authentication. This is a testbed, not a payments system.
"""

import json

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from . import ledger, webhooks

router = APIRouter()


class CreateAccountRequest(BaseModel):
    owner: str = Field(..., min_length=1, max_length=200)
    currency: str | None = Field(default=None, max_length=3)


class MovementRequest(BaseModel):
    amount: int = Field(..., gt=0, description="Amount in minor units (cents)")
    reference: str | None = Field(default=None, max_length=200)


class TransferRequest(BaseModel):
    from_account_id: str
    to_account_id: str
    amount: int = Field(..., gt=0, description="Amount in minor units (cents)")
    reference: str | None = Field(default=None, max_length=200)


def _handle(fn, *args, **kwargs):
    """Turn a LedgerError into a 400 instead of a 500."""
    try:
        return fn(*args, **kwargs)
    except ledger.LedgerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/accounts", status_code=201)
def create_account(body: CreateAccountRequest):
    """1. Create an account."""
    return _handle(ledger.create_account, body.owner, body.currency)


@router.post("/accounts/{account_id}/deposit")
def deposit(account_id: str, body: MovementRequest):
    """2. Deposit funds."""
    return _handle(ledger.deposit, account_id, body.amount, body.reference)


@router.post("/accounts/{account_id}/withdraw")
def withdraw(account_id: str, body: MovementRequest):
    """3. Withdraw funds."""
    return _handle(ledger.withdraw, account_id, body.amount, body.reference)


@router.post("/transfers")
def create_transfer(body: TransferRequest):
    """4. Transfer between two accounts, writing both ledger rows."""
    return _handle(
        ledger.transfer,
        body.from_account_id,
        body.to_account_id,
        body.amount,
        body.reference,
    )


@router.get("/accounts/{account_id}/balance")
def get_balance(account_id: str):
    """5. Get an account balance."""
    return _handle(ledger.get_balance, account_id)


@router.get("/accounts/{account_id}/transactions")
def list_transactions(account_id: str, limit: int = 100):
    """6. List transactions for an account."""
    return {
        "account_id": account_id,
        "transactions": _handle(ledger.list_transactions, account_id, limit),
    }


@router.post("/webhooks/provider")
async def provider_webhook(
    request: Request,
    x_provider_signature: str | None = Header(default=None),
):
    """7. Receive a payment-provider webhook and verify its HMAC signature."""
    payload = await request.body()

    try:
        webhooks.verify_signature(x_provider_signature, payload)
    except webhooks.WebhookError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="body is not valid JSON") from exc

    try:
        return webhooks.handle_event(event)
    except webhooks.WebhookError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ledger.LedgerError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
