from pydantic import BaseModel


class CaptchaResponse(BaseModel):
    token: str
    question: str
    expires_in: int
