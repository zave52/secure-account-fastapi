from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.users import UserResponse

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory=str(Path(__file__).parents[2] / "templates"))


def render(request: Request, name: str, context: dict, status_code: int = 200):
    return templates.TemplateResponse(request, name, context, status_code=status_code)


@router.get("/users", response_model=list[UserResponse])
async def users(_: User = Depends(require_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.id))
    return list(result.scalars().all())


@router.get("/audit")
async def audit_logs(
        email: str | None = Query(default=None),
        action: str | None = Query(default=None),
        ip: str | None = Query(default=None),
        _: User = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog).join(User, AuditLog.user_id == User.id, isouter=True)
    if email:
        query = query.where(User.email.ilike(f"%{email.strip()}%"))
    if action:
        query = query.where(AuditLog.action == action.strip())
    if ip:
        query = query.where(AuditLog.ip_address.ilike(f"%{ip.strip()}%"))
    result = await db.execute(query.add_columns(User.email).order_by(desc(AuditLog.created_at)).limit(200))
    return [
        {
            "id": item.id,
            "user_id": item.user_id,
            "email": email,
            "action": item.action,
            "ip_address": item.ip_address,
            "details": item.details,
            "created_at": item.created_at,
        }
        for item, email in result.all()
    ]


@router.post("/users/{user_id}/block")
async def block_user(
        user_id: int,
        request: Request,
        _: User = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_blocked = True
    db.add(AuditLog(user_id=user.id, action="admin_blocked_user",
                    ip_address=request.client.host if request.client else None))
    await db.commit()
    return RedirectResponse("/admin", status_code=303) if not request.url.path.startswith("/api/") else {
        "message": "User blocked."
    }


@router.post("/users/{user_id}/unblock")
async def unblock_user(
        user_id: int,
        request: Request,
        _: User = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.is_blocked = False
    user.locked_until = None
    user.failed_login_attempts = 0
    db.add(AuditLog(user_id=user.id, action="admin_unblocked_user",
                    ip_address=request.client.host if request.client else None))
    await db.commit()
    return RedirectResponse("/admin", status_code=303) if not request.url.path.startswith("/api/") else {
        "message": "User unblocked."
    }


@router.post("/users/{user_id}/make-admin")
async def make_admin(
        user_id: int,
        request: Request,
        actor: User = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    user.role = "admin"
    db.add(
        AuditLog(
            user_id=user.id,
            action="admin_granted",
            details=f"Changed by administrator ID {actor.id}",
            ip_address=request.client.host if request.client else None,
        )
    )
    await db.commit()
    result = {"message": "Administrator privileges granted."}
    return RedirectResponse("/admin", status_code=303) if not request.url.path.startswith("/api/") else result


@router.post("/users/{user_id}/remove-admin")
async def remove_admin(
        user_id: int,
        request: Request,
        actor: User = Depends(require_admin),
        db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.id == actor.id:
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator privileges.")
    user.role = "user"
    db.add(
        AuditLog(
            user_id=user.id,
            action="admin_revoked",
            details=f"Changed by administrator ID {actor.id}",
            ip_address=request.client.host if request.client else None,
        )
    )
    await db.commit()
    result = {"message": "Administrator privileges revoked."}
    return RedirectResponse("/admin", status_code=303) if not request.url.path.startswith("/api/") else result


@router.get("", response_class=HTMLResponse, include_in_schema=False)
async def admin_page(
        request: Request,
        email: str | None = None,
        action: str | None = None,
        ip: str | None = None,
        user: User | None = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
):
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user.role != "admin":
        return render(
            request, "message.html",
            {"title": "Access denied", "message": "Administrator privileges required."}, 403,
        )
    users_result = await db.execute(select(User).order_by(User.id))
    logs_query = select(AuditLog).join(User, AuditLog.user_id == User.id, isouter=True)
    if email:
        logs_query = logs_query.where(User.email.ilike(f"%{email.strip()}%"))
    if action:
        logs_query = logs_query.where(AuditLog.action == action.strip())
    if ip:
        logs_query = logs_query.where(AuditLog.ip_address.ilike(f"%{ip.strip()}%"))
    logs_result = await db.execute(
        logs_query.add_columns(User.email).order_by(desc(AuditLog.created_at)).limit(200)
    )
    failed_result = await db.execute(
        select(AuditLog.user_id, func.count(AuditLog.id))
        .where(AuditLog.action == "login_failed")
        .group_by(AuditLog.user_id)
    )
    failed_counts = {user_id: count for user_id, count in failed_result.all()}
    return render(
        request, "admin.html",
        {
            "user": user,
            "users": users_result.scalars().all(),
            "logs": [
                {"event": event, "email": email}
                for event, email in logs_result.all()
            ],
            "failed_counts": failed_counts,
            "filter_email": email or "",
            "filter_action": action or "",
            "filter_ip": ip or "",
        },
    )
