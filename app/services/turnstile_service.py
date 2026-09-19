import logging

import httpx

from app.core.config import settings

VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
logger = logging.getLogger(__name__)


def is_turnstile_configured() -> bool:
    return bool(
        settings.cloudflare_turnstile_enabled
        and settings.cloudflare_turnstile_site_key
        and settings.cloudflare_turnstile_secret_key
    )


async def verify_turnstile(token: str | None, remote_ip: str | None = None) -> bool:
    if not is_turnstile_configured() or not token:
        logger.warning(
            "Turnstile verification skipped or rejected before request: configured=%s token_present=%s",
            is_turnstile_configured(),
            bool(token),
        )
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                VERIFY_URL,
                data={
                    "secret": settings.cloudflare_turnstile_secret_key,
                    "response": token,
                    "remoteip": remote_ip or "",
                },
            )
            response.raise_for_status()
            result = response.json()
            success = result.get("success") is True
            logger.info(
                "Turnstile verification result: success=%s error_codes=%s hostname=%s action=%s",
                success,
                result.get("error-codes", []),
                result.get("hostname"),
                result.get("action"),
            )
            return success
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("Turnstile verification request failed: %s", exc)
        return False
