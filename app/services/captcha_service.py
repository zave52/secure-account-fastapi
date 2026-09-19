import random

from app.core.config import settings
from app.core.security import sign_payload, verify_payload


def create_captcha() -> tuple[str, str]:
    first, second = random.randint(2, 9), random.randint(2, 9)
    question = f"How much is {first} + {second}?"
    token = sign_payload(
        {"question": question, "answer": str(first + second)},
        settings.secret_key,
        settings.captcha_ttl_seconds,
    )
    return question, token


def verify_captcha(token: str | None, answer: str | None) -> bool:
    if not token or answer is None:
        return False
    payload = verify_payload(token, settings.secret_key)
    return bool(payload and str(payload.get("answer", "")).strip() == answer.strip())
