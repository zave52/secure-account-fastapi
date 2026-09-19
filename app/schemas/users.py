from pydantic import BaseModel, EmailStr, Field


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    is_blocked: bool
    totp_enabled: bool

    model_config = {"from_attributes": True}


class ProfileUpdate(BaseModel):
    full_name: str = Field(max_length=120)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str
