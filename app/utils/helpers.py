from datetime import datetime, timezone, timedelta
from app.core.config import settings
from app.db.models import User

from datetime import datetime, timezone
from app.db.models import User


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


