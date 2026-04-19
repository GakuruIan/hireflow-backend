from datetime import datetime, timezone, timedelta

# config
from app.core.config import settings
# models
from app.db.models import User,User,AppLogs,LogCategory,LogLevel

# helper functions
from .client_info import get_client_info

from fastapi import Request


from sqlmodel import Session


def ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None

    if dt.tzinfo is None:
        raise ValueError("Naive datetime detected")

    return dt.astimezone(timezone.utc)


def is_account_locked(user: User) -> bool:
    if not user.locked_until:
        return False

    locked_until = ensure_utc(user.locked_until)
    now = datetime.now(timezone.utc)

    if locked_until <= now:
        user.locked_until = None
        user.failed_login_attempts = 0
        return False

    return True

def handle_failed_login(user: User):
    user.failed_login_attempts += 1

    if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCOUNT_LOCK_MINUTES
        )
        user.failed_login_attempts = 0


def reset_login_attempts(user: User):
    user.failed_login_attempts = 0
    user.locked_until = None


def log_event(db: Session, user_id:str, action: str, category: LogCategory, message: str, level: LogLevel,meta_data: dict | None, request: Request | None = None):
    client_info = get_client_info(request)
    log_entry = AppLogs(
        user_id=user_id,
        action=action,
        level=level,
        category=category,
        message=message,
        meta_data=meta_data,  
        ip_address=client_info.get('ip_address'),
        os=client_info.get('os'),
        user_agent=client_info.get('user_agent'),
        browser=client_info.get('browser'),
    )
    db.add(log_entry)
    db.commit()