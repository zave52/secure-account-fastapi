from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.api.deps import get_current_user
from app.api.v1 import admin, auth, captcha, users
from app.core.config import settings
from app.core.security import hash_password
from app.db.session import SessionLocal, init_db
from app.models.user import User


async def seed_admin() -> None:
    async with SessionLocal() as db:
        existing = await db.scalar(select(User).where(User.email == settings.admin_email.lower()))
        if not existing:
            db.add(
                User(
                    email=settings.admin_email.lower(),
                    full_name="Administrator",
                    hashed_password=hash_password(settings.admin_password),
                    role="admin",
                    is_active=True,
                )
            )
            await db.commit()


@asynccontextmanager
async def lifespan(_: FastAPI):
    await init_db()
    await seed_admin()
    yield


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
templates_path = Path(__file__).parent / "templates"
app.mount("/static", StaticFiles(directory=str(templates_path / "static")), name="static")
templates = Jinja2Templates(directory=str(templates_path))

# JSON/API routes.
app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(captcha.router, prefix="/api/v1")

# HTML routes use short, human-friendly URLs. The API routers also expose the
# same HTML handlers under their namespaced paths for backwards compatibility.
app.include_router(auth.router)
app.include_router(users.html_router)
app.include_router(admin.router)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index(request: Request, user=Depends(get_current_user)):
    return templates.TemplateResponse(
        request,
        "index.html",
        {"user": user},
    )


@app.get("/login", include_in_schema=False)
async def login_alias():
    return RedirectResponse("/auth/login", status_code=307)


@app.get("/register", include_in_schema=False)
async def register_alias():
    return RedirectResponse("/auth/register", status_code=307)


@app.get("/forgot-password", include_in_schema=False)
async def forgot_alias():
    return RedirectResponse("/auth/forgot-password", status_code=307)


@app.get("/reset-password", include_in_schema=False)
async def reset_alias(token: str = ""):
    suffix = f"?token={token}" if token else ""
    return RedirectResponse(f"/auth/reset-password{suffix}", status_code=307)


@app.get("/activate/{token}", include_in_schema=False)
async def activate_alias(token: str):
    return RedirectResponse(f"/auth/activate/{token}", status_code=307)


@app.get("/activate", include_in_schema=False)
async def activate_query_alias(token: str = ""):
    if not token:
        return HTMLResponse("Activation token is missing.", status_code=400)
    return RedirectResponse(f"/auth/activate/{token}", status_code=307)


def run() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
