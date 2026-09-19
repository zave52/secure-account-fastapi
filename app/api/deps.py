from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import token_digest
from app.db.session import get_db
from app.models.token import SessionToken
from app.models.user import User


async def get_current_user(
        request: Request, db: AsyncSession = Depends(get_db)
) -> User | None:
    raw = request.cookies.get("session")
    if not raw:
        return None
    result = await db.execute(
        select(SessionToken)
        .where(SessionToken.token_hash == token_digest(raw), SessionToken.revoked_at.is_(None))
    )
    session = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if not session or session.expires_at.replace(tzinfo=timezone.utc) < now:
        return None
    user_result = await db.execute(select(User).where(User.id == session.user_id))
    return user_result.scalar_one_or_none()


async def require_user(user: User | None = Depends(get_current_user)) -> User:
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
    return user


async def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator privileges required.")
    return user
