from fastapi import APIRouter

from app.core.config import settings
from app.schemas.captcha import CaptchaResponse
from app.services.captcha_service import create_captcha

router = APIRouter(prefix="/captcha", tags=["captcha"])


@router.get("", response_model=CaptchaResponse)
async def captcha() -> CaptchaResponse:
    question, token = create_captcha()
    return CaptchaResponse(token=token, question=question, expires_in=settings.captcha_ttl_seconds)
