"""Клиент Platega API: СБП (QR), создание платежа и проверка статуса без вебхуков."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

BASE_URL = "https://app.platega.io"
PAYMENT_METHOD_SBP_QR = 2
DEFAULT_TIMEOUT = 30.0


class PlategaError(Exception):
    """Ошибка вызова Platega (сеть, 4xx/5xx, неверный ответ)."""

    def __init__(self, message: str, *, status_code: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


@dataclass(frozen=True)
class CreatedTransaction:
    transaction_id: str
    redirect_url: str
    status: str
    expires_in: Optional[str] = None


@dataclass(frozen=True)
class TransactionStatus:
    transaction_id: str
    status: str
    payload: Optional[str] = None
    amount: Optional[float] = None
    currency: Optional[str] = None


def _headers(merchant_id: str, secret: str) -> dict[str, str]:
    return {
        "X-MerchantId": merchant_id.strip(),
        "X-Secret": secret.strip(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _platega_error_message(status_code: int, data: Any) -> str:
    if isinstance(data, dict):
        for key in ("message", "error", "detail", "title"):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        errs = data.get("errors")
        if isinstance(errs, list) and errs:
            return str(errs[0])
    if isinstance(data, str) and data.strip():
        return data.strip()
    return f"HTTP {status_code}"


async def create_sbp_transaction(
    *,
    merchant_id: str,
    secret: str,
    amount_rub: float,
    description: str,
    payload: str,
    return_url: Optional[str] = None,
    failed_url: Optional[str] = None,
    client: Optional[httpx.AsyncClient] = None,
) -> CreatedTransaction:
    """
    POST /transaction/process — СБП QR (paymentMethod 2).
    Сумма и валюта по документации Platega.
    """
    body: dict[str, Any] = {
        "paymentMethod": PAYMENT_METHOD_SBP_QR,
        "paymentDetails": {
            "amount": float(amount_rub),
            "currency": "RUB",
        },
        "description": description[:500] if description else "Оплата",
        "payload": payload[:1000] if payload else "",
    }
    if return_url:
        body["return"] = return_url
    if failed_url:
        body["failedUrl"] = failed_url

    close_client = client is None
    http = client or httpx.AsyncClient(base_url=BASE_URL, timeout=DEFAULT_TIMEOUT)

    try:
        resp = await http.post(
            "/transaction/process",
            json=body,
            headers=_headers(merchant_id, secret),
        )
        data = _safe_json(resp)
        if resp.status_code >= 400:
            raise PlategaError(
                _platega_error_message(resp.status_code, data),
                status_code=resp.status_code,
                body=data,
            )
        if not isinstance(data, dict):
            raise PlategaError("Пустой или неверный ответ Platega", status_code=resp.status_code, body=data)

        tx_id = data.get("transactionId") or data.get("transaction_id") or data.get("id")
        redirect = data.get("redirect") or data.get("redirectUrl")
        status = str(data.get("status") or "PENDING")
        if not tx_id or not redirect:
            raise PlategaError(
                "В ответе нет transactionId или redirect",
                status_code=resp.status_code,
                body=data,
            )
        expires = data.get("expiresIn")
        expires_str = str(expires) if expires is not None else None
        return CreatedTransaction(
            transaction_id=str(tx_id),
            redirect_url=str(redirect),
            status=status,
            expires_in=expires_str,
        )
    finally:
        if close_client:
            await http.aclose()


async def get_transaction_status(
    *,
    merchant_id: str,
    secret: str,
    transaction_id: str,
    client: Optional[httpx.AsyncClient] = None,
) -> TransactionStatus:
    """GET /transaction/{id} — статус платежа."""
    close_client = client is None
    http = client or httpx.AsyncClient(base_url=BASE_URL, timeout=DEFAULT_TIMEOUT)
    try:
        resp = await http.get(
            f"/transaction/{transaction_id}",
            headers=_headers(merchant_id, secret),
        )
        data = _safe_json(resp)
        if resp.status_code == 404:
            raise PlategaError("Транзакция не найдена", status_code=404, body=data)
        if resp.status_code >= 400:
            raise PlategaError(
                _platega_error_message(resp.status_code, data),
                status_code=resp.status_code,
                body=data,
            )
        if not isinstance(data, dict):
            raise PlategaError("Пустой или неверный ответ Platega", status_code=resp.status_code, body=data)

        tid = str(data.get("id") or transaction_id)
        status = str(data.get("status") or "UNKNOWN")
        payload = data.get("payload")
        payload_str = str(payload) if payload is not None else None

        amount: Optional[float] = None
        currency: Optional[str] = None
        pd = data.get("paymentDetails")
        if isinstance(pd, dict):
            try:
                if pd.get("amount") is not None:
                    amount = float(pd["amount"])
            except (TypeError, ValueError):
                amount = None
            cur = pd.get("currency")
            if isinstance(cur, str):
                currency = cur

        return TransactionStatus(
            transaction_id=tid,
            status=status.upper() if status else "UNKNOWN",
            payload=payload_str,
            amount=amount,
            currency=currency,
        )
    finally:
        if close_client:
            await http.aclose()


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text or None


def build_telegram_payload(telegram_user_id: int) -> str:
    """Строка payload для Platega; сверяем при проверке статуса."""
    return f"tg:{telegram_user_id}"
