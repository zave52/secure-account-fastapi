from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_user
from app.core.password_policy import validate_password
from app.core.security import hash_password, token_digest, verify_password
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.token import SessionToken
from app.models.user import User
from app.schemas.users import PasswordChange, ProfileUpdate, UserResponse
from app.services.totp_service import create_totp, qr_code_for_secret, valid_code

router = APIRouter(prefix="/users", tags=["users"])
html_router = APIRouter(tags=["html"])
templates = Jinja2Templates(directory=str(Path(__file__).parents[2] / "templates"))


def render(request: Request, name: str, context: dict):
    return templates.TemplateResponse(request, name, context)


@router.get("/me", response_model=UserResponse)
async def me(user: User = Depends(require_user)) -> User:
    return user


@router.patch("/me", response_model=UserResponse)
async def update_me(
        data: ProfileUpdate, request: Request, user: User = Depends(require_user),
        db: AsyncSession = Depends(get_db),
) -> User:
    user.full_name = data.full_name.strip()
    db.add(
        AuditLog(user_id=user.id, action="profile_updated", ip_address=request.client.host if request.client else None))
    await db.commit()
    return user


@router.post("/me/password")
async def change_password(
        data: PasswordChange, request: Request, user: User = Depends(require_user),
        db: AsyncSession = Depends(get_db),
):
    if not user.hashed_password or not verify_password(data.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    errors = validate_password(data.new_password)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    user.hashed_password = hash_password(data.new_password)
    await db.execute(
        update(SessionToken)
        .where(SessionToken.user_id == user.id, SessionToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    db.add(AuditLog(user_id=user.id, action="password_changed",
                    ip_address=request.client.host if request.client else None))
    await db.commit()
    return {"message": "Password changed."}


@router.post("/me/totp/setup")
async def totp_setup(
        user: User = Depends(require_user), db: AsyncSession = Depends(get_db)
):
    secret, qr_data = create_totp(user.email)
    user.totp_secret = secret
    user.totp_enabled = False
    await db.commit()
    return {"message": "Scan the QR code and confirm the code.", "qr_code": qr_data}


@router.post("/me/totp/confirm")
async def totp_confirm(
        code: str = Form(...), request: Request = None, user: User = Depends(require_user),
        db: AsyncSession = Depends(get_db),
):
    if not valid_code(user.totp_secret, code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code.")
    user.totp_enabled = True
    db.add(AuditLog(user_id=user.id, action="totp_enabled",
                    ip_address=request.client.host if request and request.client else None))
    await db.commit()
    return {"message": "Two-factor authentication enabled."}


@router.delete("/me/totp")
async def totp_disable(
        request: Request, user: User = Depends(require_user), db: AsyncSession = Depends(get_db)
):
    user.totp_enabled = False
    user.totp_secret = None
    db.add(
        AuditLog(user_id=user.id, action="totp_disabled", ip_address=request.client.host if request.client else None))
    await db.commit()
    return {"message": "Two-factor authentication disabled."}


@router.get("/profile", response_class=HTMLResponse, include_in_schema=False)
async def profile(request: Request, user: User | None = Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login", status_code=303)
    return render(request, "profile.html", {"user": user})


@html_router.get("/profile", response_class=HTMLResponse, include_in_schema=False)
@html_router.get("/users/profile", response_class=HTMLResponse, include_in_schema=False)
async def profile_page(request: Request, user: User | None = Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login", status_code=303)
    return render(request, "profile.html", {"user": user})


@router.post("/profile", response_class=HTMLResponse, include_in_schema=False)
@html_router.post("/users/profile", response_class=HTMLResponse, include_in_schema=False)
async def profile_form(
        request: Request, full_name: str = Form(...), user: User | None = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
):
    if not user:
        return RedirectResponse("/login", status_code=303)
    user.full_name = full_name.strip()
    await db.commit()
    return RedirectResponse("/profile", status_code=303)


@router.post("/profile/password", response_class=HTMLResponse, include_in_schema=False)
@html_router.post("/users/profile/password", response_class=HTMLResponse, include_in_schema=False)
async def profile_password_form(
        request: Request,
        current_password: str = Form(""),
        new_password: str = Form(""),
        confirm_password: str = Form(""),
        user: User | None = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
):
    if not user:
        return RedirectResponse("/login", status_code=303)

    error = None
    if not user.hashed_password or not verify_password(current_password, user.hashed_password):
        error = "Current password is incorrect."
    elif new_password != confirm_password:
        error = "New passwords do not match."
    else:
        password_errors = validate_password(new_password)
        if password_errors:
            error = " ".join(password_errors)

    if error:
        return render(request, "profile.html", {"user": user, "password_error": error})

    user.hashed_password = hash_password(new_password)
    current_session = request.cookies.get("session")
    session_query = update(SessionToken).where(SessionToken.user_id == user.id)
    if current_session:
        session_query = session_query.where(
            SessionToken.token_hash != token_digest(current_session)
        )
    session_query = session_query.values(revoked_at=datetime.now(timezone.utc))
    await db.execute(session_query)
    db.add(AuditLog(
        user_id=user.id,
        action="password_changed",
        ip_address=request.client.host if request.client else None,
    ))
    await db.commit()
    return render(request, "profile.html", {
        "user": user,
        "message": "Password changed successfully. Other active sessions were signed out.",
    })


@router.post("/profile/totp", response_class=HTMLResponse, include_in_schema=False)
@html_router.post("/profile/totp", response_class=HTMLResponse, include_in_schema=False)
@html_router.post("/users/profile/totp", response_class=HTMLResponse, include_in_schema=False)
async def profile_totp(
        request: Request, code: str = Form(""), action: str = Form("confirm"),
        user: User | None = Depends(get_current_user), db: AsyncSession = Depends(get_db),
):
    if not user:
        return RedirectResponse("/login", status_code=303)
    message = ""
    if action == "setup":
        secret, qr_data = create_totp(user.email)
        user.totp_secret = secret
        await db.commit()
        return render(request, "profile.html", {"user": user, "qr_code": qr_data})
    if action == "show":
        if not user.totp_secret:
            return render(request, "profile.html", {"user": user, "message": "Create a QR code first."})
        qr_data = qr_code_for_secret(user.totp_secret, user.email)
        return render(request, "profile.html", {"user": user, "qr_code": qr_data})
    if action == "disable":
        user.totp_enabled = False
        user.totp_secret = None
        message = "TOTP disabled."
    elif valid_code(user.totp_secret, code):
        user.totp_enabled = True
        message = "TOTP enabled."
    else:
        message = "Invalid code."
    await db.commit()
    return render(request, "profile.html", {"user": user, "message": message})
