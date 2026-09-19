import hmac
import logging
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.password_policy import validate_password
from app.core.security import (
    hash_password,
    random_token,
    sign_payload,
    token_digest,
    verify_password,
    verify_payload,
)
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.token import AccountToken, SessionToken
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    RegisterRequest,
    ResetPasswordRequest,
)
from app.services.captcha_service import create_captcha, verify_captcha
from app.services.email_service import email_service
from app.services.totp_service import valid_code
from app.services.turnstile_service import is_turnstile_configured, verify_turnstile

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(Path(__file__).parents[2] / "templates"))


def now() -> datetime:
    return datetime.now(timezone.utc)


def lock_message(locked_until: datetime) -> str:
    remaining_seconds = max(0, math.ceil((locked_until - now()).total_seconds()))
    minutes, seconds = divmod(remaining_seconds, 60)
    if minutes:
        duration = f"{minutes} min."
        if seconds:
            duration += f" {seconds} sec."
    else:
        duration = f"{seconds} sec."
    until = locked_until.astimezone(timezone.utc).strftime("%H:%M:%S UTC")
    return f"Account temporarily locked for {duration}. It will be unlocked at {until}."


def render(request: Request, name: str, context: dict, status_code: int = 200):
    return templates.TemplateResponse(request, name, context, status_code=status_code)


async def audit(db: AsyncSession, request: Request, action: str, user_id: int | None = None):
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            ip_address=request.client.host if request.client else None,
        )
    )


async def create_session(db: AsyncSession, user: User, response) -> None:
    raw = random_token()
    db.add(
        SessionToken(
            user_id=user.id,
            token_hash=token_digest(raw),
            expires_at=now() + timedelta(minutes=settings.session_ttl_minutes),
        )
    )
    await db.commit()
    response.set_cookie(
        "session",
        raw,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
    )


async def register_user(data: RegisterRequest, request: Request, db: AsyncSession) -> User:
    errors = validate_password(data.password)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    email = str(data.email).lower()
    if await db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="A user with this email already exists.")
    user = User(
        email=email,
        full_name=data.full_name.strip(),
        hashed_password=hash_password(data.password),
        is_active=False,
    )
    db.add(user)
    await db.flush()
    raw = random_token()
    db.add(
        AccountToken(
            user_id=user.id,
            kind="activation",
            token_hash=token_digest(raw),
            expires_at=now() + timedelta(hours=settings.token_ttl_hours),
        )
    )
    await audit(db, request, "registration", user.id)
    await db.commit()
    url = str(request.base_url).rstrip("/") + f"/activate/{raw}"
    await email_service.send(user.email, "Account activation", f"Follow this link to activate your account:\n{url}")
    return user


async def authenticate(data: LoginRequest, request: Request, db: AsyncSession) -> User:
    email = str(data.email).lower()
    user = await db.scalar(select(User).where(User.email == email))
    if user and user.is_blocked:
        await audit(db, request, "login_blocked", user.id)
        await db.commit()
        raise HTTPException(status_code=423, detail="This account was blocked by an administrator.")
    if user and user.locked_until:
        locked_until = user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now():
            await audit(db, request, "login_locked", user.id)
            await db.commit()
            raise HTTPException(status_code=423, detail=lock_message(locked_until))
        user.locked_until = None
        user.failed_login_attempts = 0
    if not user or not user.hashed_password or not verify_password(data.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = now() + timedelta(minutes=settings.lockout_minutes)
            await audit(db, request, "login_failed", user.id)
            await db.commit()
            if user.locked_until:
                raise HTTPException(status_code=423, detail=lock_message(user.locked_until))
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Activate your account using the link in the email.")
    if user.totp_enabled and not valid_code(user.totp_secret, data.totp_code):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.max_login_attempts:
            user.locked_until = now() + timedelta(minutes=settings.lockout_minutes)
        await audit(db, request, "totp_failed", user.id)
        await audit(db, request, "login_failed", user.id)
        await db.commit()
        if user.locked_until:
            raise HTTPException(status_code=423, detail=lock_message(user.locked_until))
        raise HTTPException(status_code=401, detail="Enter a valid two-factor authentication code.")
    user.failed_login_attempts = 0
    user.locked_until = None
    await audit(db, request, "login_success", user.id)
    await db.commit()
    return user


async def authenticate_web_password(email: str, password: str, request: Request, db: AsyncSession) -> User:
    """Validate the first web-login step without completing MFA."""
    normalized_email = email.lower().strip()
    user = await db.scalar(select(User).where(User.email == normalized_email))
    if user and user.is_blocked:
        await audit(db, request, "login_blocked", user.id)
        await db.commit()
        raise HTTPException(status_code=423, detail="This account was blocked by an administrator.")
    if user and user.locked_until:
        locked_until = user.locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now():
            raise HTTPException(status_code=423, detail=lock_message(locked_until))
        user.locked_until = None
        user.failed_login_attempts = 0
    if not user or not user.hashed_password or not verify_password(password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = now() + timedelta(minutes=settings.lockout_minutes)
            await audit(db, request, "login_failed", user.id)
            await db.commit()
            if user.locked_until:
                raise HTTPException(status_code=423, detail=lock_message(user.locked_until))
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Activate your account using the link in the email.")
    return user


@router.get("/captcha")
async def auth_captcha():
    question, token = create_captcha()
    return {"captcha_id": token.split(".", 1)[0], "token": token, "question": question,
            "expires_in": settings.captcha_ttl_seconds}


@router.post("/register", status_code=201)
async def register(data: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    if is_turnstile_configured():
        captcha_valid = await verify_turnstile(data.turnstile_token, request.client.host if request.client else None)
    else:
        captcha_valid = verify_captcha(data.captcha_token, data.captcha_answer)
    if not captcha_valid:
        raise HTTPException(status_code=400, detail="CAPTCHA is required and must be valid.")
    user = await register_user(data, request, db)
    return {"message": "Registration complete. Check your email to activate the account.", "user_id": user.id}


@router.post("/login")
async def login(data: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    if is_turnstile_configured():
        valid = await verify_turnstile(data.turnstile_token, request.client.host if request.client else None)
        if not valid:
            raise HTTPException(status_code=400, detail="CAPTCHA is required and must be valid.")
    user = await authenticate(data, request, db)
    response = JSONResponse({"message": "Login successful.", "user_id": user.id})
    await create_session(db, user, response)
    return response


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    raw = request.cookies.get("session")
    if raw:
        session = await db.scalar(select(SessionToken).where(SessionToken.token_hash == token_digest(raw)))
        if session:
            session.revoked_at = now()
            await db.commit()
    response = (
        JSONResponse({"message": "Logout successful."})
        if request.url.path.startswith("/api/")
        else RedirectResponse("/", status_code=303)
    )
    response.delete_cookie("session")
    return response


@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(User).where(User.email == str(data.email).lower()))
    if user:
        raw = random_token()
        db.add(AccountToken(user_id=user.id, kind="reset", token_hash=token_digest(raw),
                            expires_at=now() + timedelta(minutes=15)))
        await audit(db, request, "password_reset_requested", user.id)
        await db.commit()
        url = str(request.base_url).rstrip("/") + f"/reset-password?token={raw}"
        await email_service.send(user.email, "Password reset", f"This one-time link is valid for 15 minutes:\n{url}")
    return {"message": "If the address exists, a password reset link has been sent."}


@router.post("/reset-password")
async def reset_password(data: ResetPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)):
    errors = validate_password(data.password)
    if errors:
        raise HTTPException(status_code=422, detail=errors)
    token = await db.scalar(select(AccountToken).where(
        AccountToken.token_hash == token_digest(data.token),
        AccountToken.kind == "reset",
        AccountToken.used_at.is_(None),
    ))
    if not token or token.expires_at.replace(tzinfo=timezone.utc) < now():
        raise HTTPException(status_code=400, detail="Invalid or expired token.")
    user = await db.get(User, token.user_id)
    user.hashed_password = hash_password(data.password)
    token.used_at = now()
    await db.execute(
        update(SessionToken)
        .where(SessionToken.user_id == user.id, SessionToken.revoked_at.is_(None))
        .values(revoked_at=now())
    )
    await audit(db, request, "password_reset", user.id)
    await db.commit()
    return {"message": "Password changed successfully."}


OAUTH_PROVIDERS = {
    "google": {
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "scopes": "openid email profile",
    },
    "github": {
        "authorize": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "scopes": "read:user user:email",
    },
}


def oauth_credentials(provider: str) -> tuple[str | None, str | None]:
    if provider == "google":
        return settings.google_client_id, settings.google_client_secret
    return settings.github_client_id, settings.github_client_secret


def oauth_redirect_uri(request: Request, provider: str) -> str:
    base = (settings.oauth_redirect_base_url or str(request.base_url).rstrip("/")).rstrip("/")
    return f"{base}/auth/oauth/{provider}/callback"


@router.get("/oauth/{provider}")
async def oauth_start(provider: str, request: Request):
    if provider not in {"google", "github"}:
        raise HTTPException(status_code=404, detail="Unknown OAuth provider.")
    client_id, client_secret = oauth_credentials(provider)
    if not client_id or not client_secret:
        raise HTTPException(
            status_code=503,
            detail=f"OAuth {provider} is not configured. Add the client ID and client secret to .env.",
        )
    state = sign_payload({"provider": provider, "nonce": random_token()}, settings.secret_key, 600)
    params = {
        "client_id": client_id,
        "redirect_uri": oauth_redirect_uri(request, provider),
        "state": state,
        "scope": OAUTH_PROVIDERS[provider]["scopes"],
    }
    if provider == "google":
        params.update({"response_type": "code", "access_type": "offline", "prompt": "select_account"})
    response = RedirectResponse(
        f"{OAUTH_PROVIDERS[provider]['authorize']}?{urlencode(params)}",
        status_code=303,
    )
    response.set_cookie("oauth_state", state, max_age=600, httponly=True, secure=settings.cookie_secure,
                        samesite="lax")
    return response


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
        provider: str,
        request: Request,
        state: str | None = None,
        code: str | None = None,
        error: str | None = None,
        db: AsyncSession = Depends(get_db),
):
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=404, detail="Unknown OAuth provider.")
    if error:
        raise HTTPException(status_code=400, detail=f"OAuth authorization was denied: {error}.")
    if not state or not code or not hmac.compare_digest(state, request.cookies.get("oauth_state", "")):
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")
    payload = verify_payload(state, settings.secret_key)
    if not payload or payload.get("provider") != provider:
        raise HTTPException(status_code=400, detail="Invalid OAuth state.")
    client_id, client_secret = oauth_credentials(provider)
    if not client_id or not client_secret:
        raise HTTPException(status_code=503, detail=f"OAuth {provider} is not configured.")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_response = await client.post(
                OAUTH_PROVIDERS[provider]["token"],
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": oauth_redirect_uri(request, provider),
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
            if token_response.is_error:
                try:
                    provider_error = token_response.json().get("error_description") or token_response.json().get(
                        "error")
                except ValueError:
                    provider_error = None
                detail = f"{provider}: unable to obtain an access token."
                if provider_error:
                    detail += f" Reason: {provider_error}."
                raise HTTPException(status_code=502, detail=detail)
            token_data = token_response.json()
            access_token = token_data.get("access_token")
            if not access_token:
                raise HTTPException(status_code=502, detail=f"{provider}: the provider did not return an access token.")
            headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
            if provider == "google":
                profile_response = await client.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers)
                profile = profile_response.json()
                email = profile.get("email")
                full_name = profile.get("name") or email
                verified = profile.get("email_verified") is True
            else:
                profile_response = await client.get("https://api.github.com/user", headers=headers)
                profile = profile_response.json()
                email_response = await client.get("https://api.github.com/user/emails", headers=headers)
                emails = email_response.json()
                verified_email = next(
                    (item["email"] for item in emails if item.get("primary") and item.get("verified")),
                    None,
                )
                email = verified_email
                full_name = profile.get("name") or profile.get("login") or email
                verified = email is not None
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail=f"{provider}: OAuth provider timed out.") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"{provider}: connection error with OAuth provider.") from exc
    if profile_response.is_error or not email or not verified:
        raise HTTPException(status_code=502, detail=f"{provider}: the account email was not verified.")
    email = str(email).lower()
    user = await db.scalar(select(User).where(User.email == email))
    if user and user.is_blocked:
        raise HTTPException(status_code=423, detail="This account was blocked by an administrator.")
    if not user:
        user = User(email=email, full_name=full_name, is_active=True)
        db.add(user)
        await db.flush()
    await audit(db, request, "oauth_login", user.id)
    await db.commit()
    response = RedirectResponse("/profile", status_code=303)
    response.delete_cookie("oauth_state")
    await create_session(db, user, response)
    return response


@router.get("/activate/{token}")
async def activate(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    record = await db.scalar(select(AccountToken).where(
        AccountToken.token_hash == token_digest(token),
        AccountToken.kind == "activation",
        AccountToken.used_at.is_(None),
    ))
    if not record or record.expires_at.replace(tzinfo=timezone.utc) < now():
        raise HTTPException(status_code=400, detail="Invalid or expired activation link.")
    user = await db.get(User, record.user_id)
    user.is_active = True
    record.used_at = now()
    await audit(db, request, "account_activated", user.id)
    await db.commit()
    return RedirectResponse("/login?activated=1", status_code=303)


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    return render(request, "login.html", {
        "step": "credentials",
        "cloudflare_turnstile_enabled": is_turnstile_configured(),
        "turnstile_site_key": settings.cloudflare_turnstile_site_key,
    })


@router.post("/login-form", response_class=HTMLResponse, include_in_schema=False)
async def login_form(request: Request, email: str = Form(...), password: str = Form(""),
                     totp_code: str = Form(""), captcha_token: str = Form(""),
                     captcha_answer: str = Form(""), pending_token: str = Form(""),
                     turnstile_token: str = Form(""),
                     cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
                     step: str = Form("credentials"),
                     db: AsyncSession = Depends(get_db)):
    requires_mfa = False
    try:
        if step == "credentials":
            user = await authenticate_web_password(email, password, request, db)
            pending_token = sign_payload(
                {"user_id": user.id},
                settings.secret_key,
                300,
            )
            question, captcha_token = create_captcha()
            return render(
                request,
                "login.html",
                {
                    "step": "verification",
                    "email": user.email,
                    "pending_token": pending_token,
                    "question": question,
                    "captcha_token": captcha_token,
                    "requires_mfa": user.totp_enabled,
                    "cloudflare_turnstile_enabled": is_turnstile_configured(),
                    "turnstile_site_key": settings.cloudflare_turnstile_site_key,
                },
            )
        payload = verify_payload(pending_token, settings.secret_key)
        if is_turnstile_configured():
            turnstile_token = cf_turnstile_response or turnstile_token
            logger.info(
                "Web login verification submitted: email=%s turnstile_token_present=%s token_length=%s",
                email,
                bool(turnstile_token),
                len(turnstile_token),
            )
            captcha_valid = await verify_turnstile(
                turnstile_token,
                request.client.host if request.client else None,
            )
        else:
            captcha_valid = verify_captcha(captcha_token, captcha_answer)
        if not payload or not captcha_valid:
            raise HTTPException(status_code=400, detail="Invalid or expired CAPTCHA.")
        user = await db.get(User, int(payload["user_id"]))
        if not user or user.is_blocked or not user.is_active:
            raise HTTPException(status_code=401, detail="The login session cannot be completed.")
        requires_mfa = user.totp_enabled
        if user.totp_enabled and not valid_code(user.totp_secret, totp_code):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = now() + timedelta(minutes=settings.lockout_minutes)
            await audit(db, request, "totp_failed", user.id)
            await audit(db, request, "login_failed", user.id)
            await db.commit()
            if user.locked_until:
                raise HTTPException(status_code=423, detail=lock_message(user.locked_until))
            raise HTTPException(status_code=401, detail="Enter a valid MFA code.")
        user.failed_login_attempts = 0
        user.locked_until = None
        await audit(db, request, "login_success", user.id)
        await db.commit()
        response = RedirectResponse("/profile", status_code=303)
        await create_session(db, user, response)
        return response
    except HTTPException as exc:
        if step == "verification" and pending_token:
            pending_payload = verify_payload(pending_token, settings.secret_key)
            if pending_payload:
                pending_user = await db.get(User, int(pending_payload["user_id"]))
                requires_mfa = bool(pending_user and pending_user.totp_enabled)
        question, token = create_captcha()
        return render(request, "login.html", {
            "error": exc.detail,
            "step": "verification" if step == "verification" else "credentials",
            "email": email,
            "pending_token": pending_token,
            "question": question,
            "captcha_token": token,
            "turnstile_token": turnstile_token,
            "cloudflare_turnstile_enabled": is_turnstile_configured(),
            "turnstile_site_key": settings.cloudflare_turnstile_site_key,
            "requires_mfa": requires_mfa,
        }, exc.status_code)


@router.get("/register", response_class=HTMLResponse, include_in_schema=False)
async def register_page(request: Request):
    question, token = create_captcha()
    return render(request, "register.html", {
        "question": question,
        "captcha_token": token,
        "cloudflare_turnstile_enabled": is_turnstile_configured(),
        "turnstile_site_key": settings.cloudflare_turnstile_site_key,
    })


@router.post("/register-form", response_class=HTMLResponse, include_in_schema=False)
async def register_form(request: Request, email: str = Form(...), full_name: str = Form(""),
                        password: str = Form(...), captcha_token: str = Form(""),
                        captcha_answer: str = Form(""), turnstile_token: str = Form(""),
                        cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
                        db: AsyncSession = Depends(get_db)):
    try:
        data = RegisterRequest(email=email, full_name=full_name, password=password,
                               captcha_token=captcha_token, captcha_answer=captcha_answer,
                               turnstile_token=turnstile_token)
        if is_turnstile_configured():
            turnstile_token = cf_turnstile_response or turnstile_token
            logger.info(
                "Web registration submitted: email=%s turnstile_token_present=%s token_length=%s",
                email,
                bool(turnstile_token),
                len(turnstile_token),
            )
            captcha_valid = await verify_turnstile(
                turnstile_token,
                request.client.host if request.client else None,
            )
        else:
            captcha_valid = verify_captcha(captcha_token, captcha_answer)
        if not captcha_valid:
            raise HTTPException(status_code=400, detail="Invalid CAPTCHA.")
        await register_user(data, request, db)
        return render(request, "message.html", {"title": "Registration complete",
                                                "message": "Check the local outbox or your email to activate the account."})
    except HTTPException as exc:
        question, token = create_captcha()
        return render(
            request,
            "register.html",
            {
                "error": exc.detail,
                "question": question,
                "captcha_token": token,
                "cloudflare_turnstile_enabled": is_turnstile_configured(),
                "turnstile_site_key": settings.cloudflare_turnstile_site_key,
                "email": email,
                "full_name": full_name,
            },
            exc.status_code,
        )


@router.get("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
async def forgot_page(request: Request):
    return render(request, "forgot_password.html", {})


@router.post("/forgot-password-form", response_class=HTMLResponse, include_in_schema=False)
async def forgot_form(request: Request, email: str = Form(...), db: AsyncSession = Depends(get_db)):
    await forgot_password(ForgotPasswordRequest(email=email), request, db)
    return render(request, "message.html", {"title": "Check your email",
                                            "message": "If the address exists, a reset link has been sent."})


@router.get("/reset-password", response_class=HTMLResponse, include_in_schema=False)
async def reset_page(request: Request, token: str = ""):
    return render(request, "reset_password.html", {"token": token})


@router.post("/reset-password-form", response_class=HTMLResponse, include_in_schema=False)
async def reset_form(request: Request, token: str = Form(...), password: str = Form(...),
                     db: AsyncSession = Depends(get_db)):
    try:
        await reset_password(ResetPasswordRequest(token=token, password=password), request, db)
        return render(request, "message.html", {"title": "Password changed", "message": "You can now sign in."})
    except HTTPException as exc:
        return render(request, "reset_password.html", {"token": token, "error": exc.detail}, exc.status_code)
