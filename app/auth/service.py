from sqlmodel import Session, select
from fastapi import HTTPException,status,Response,Request
# models
from app.db.models import User, VerificationCode ,VerificationPurpose,Session as UserSession,LogCategory,LogLevel

# security
from app.core.security import hash_password,decode_verification_token,hash_verification_code,verify_verification_code ,verify_password ,create_refresh_token,hash_refresh_token,create_access_token,decode_refresh_token,verify_refresh_token,create_verification_token

# schemas
from app.auth.schema import RegisterSchema,  UserResponse,PasswordResetSchema,MessageResponse

# utils functions
from app.utils.code import generate_verification_code
from app.utils.client_info import get_client_info
from app.utils.helpers import is_account_locked, handle_failed_login, reset_login_attempts,log_event

# email service
from app.emails.service import send_verification_email,send_password_reset_email

# settings
from app.core.config import settings

# datetime
from datetime import datetime, timezone,timedelta
import secrets


REFRESH_COOKIE_PATH = "/auth"
REFRESH_CSRF_COOKIE_NAME = "refresh_csrf_token"
REFRESH_CSRF_HEADER_NAME = "x-csrf-token"


def _new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str, refresh_csrf_token: str) -> None:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=3600,
        expires=3600,
        samesite="lax",
        path="/",
        secure=settings.ENVIRONMENT == "production",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=7 * 24 * 3600,
        expires=7 * 24 * 3600,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
        secure=settings.ENVIRONMENT == "production",
    )
    response.set_cookie(
        key=REFRESH_CSRF_COOKIE_NAME,
        value=refresh_csrf_token,
        httponly=False,
        max_age=7 * 24 * 3600,
        expires=7 * 24 * 3600,
        samesite="lax",
        path="/auth/refresh-token",
        secure=settings.ENVIRONMENT == "production",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path=REFRESH_COOKIE_PATH)
    response.delete_cookie(key=REFRESH_CSRF_COOKIE_NAME, path="/auth/refresh-token")


def _validate_refresh_csrf(request: Request) -> None:
    if settings.ENVIRONMENT != "production":
        return

    csrf_cookie = request.cookies.get(REFRESH_CSRF_COOKIE_NAME)
    csrf_header = request.headers.get(REFRESH_CSRF_HEADER_NAME)
    if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")


def get_user_by_email(db: Session, email: str):
    return db.exec(select(User).where(User.email == email)).first()

def create_verification_code(db: Session, user_id: str, code: str, purpose: VerificationPurpose):
    new_code = VerificationCode(
        user_id=user_id,
        code=hash_verification_code(code),
        type=purpose
    )
    db.add(new_code)
    db.commit()
    db.refresh(new_code)
    return new_code

def create_session(db: Session, request: Request, user: dict):
    refresh_token = create_refresh_token(data={"sub": user.email, "scope": "refresh_token"})
    client_info = get_client_info(request)
    
    session = UserSession(
        user_id=user.id,
        device_name=client_info.get('device_name'),
        ip_address=client_info.get('ip_address'),
        os=client_info.get('os'),
        user_agent=client_info.get('user_agent'),
        browser=client_info.get('browser'),
        refresh_token=hash_refresh_token(refresh_token),
        refresh_token_expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    
    db.add(session)
    db.commit()
    db.refresh(session)

    return refresh_token

def register_user(db: Session, request: Request, register_data: RegisterSchema) -> UserResponse:
    existing_user = get_user_by_email(db, register_data.email)

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    new_user = User(
        fullname=register_data.fullname,
        email=register_data.email,
        password=hash_password(register_data.password),
        role=register_data.role,
        is_verified=False,
        failed_login_attempts=0
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    code = generate_verification_code()
    create_verification_code(db, new_user.id, code, VerificationPurpose.EMAIL_VERIFICATION)
    send_verification_email(fullname=new_user.fullname, email=new_user.email, verification_code=code, expiry=settings.VERIFICATION_CODE_EXPIRY_MINUTES)
    
    log_event(db, user_id=str(new_user.id), action="user_registered_successfully", category=LogCategory.AUTH, message="New user registered", level=LogLevel.INFO, meta_data={"email": new_user.email}, request=request)
    
    return UserResponse.model_validate(new_user)

def verify_email_service(db: Session, response: Response, request: Request, code: str, verification_token: str) -> UserResponse:
    payload = decode_verification_token(verification_token)
    if not payload or payload.get("scope") != "email_verification":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already verified")
    
    codes = db.exec(select(VerificationCode).where(
        VerificationCode.user_id == user.id,
        VerificationCode.type == VerificationPurpose.EMAIL_VERIFICATION,
        VerificationCode.used == False
    )).all()
    
    if not codes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid verification code found")
    
    verification_code = None
    for code_entry in codes:
        if code_entry.expires_at < datetime.now(timezone.utc):
            continue
        if verify_verification_code(code, code_entry.code):
            verification_code = code_entry
            break

    if not verification_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification code")
    
    user.is_verified = True
    user.verified_at = datetime.now(timezone.utc)
    verification_code.used = True
    verification_code.used_at = datetime.now(timezone.utc)
    
    db.add(user)
    db.add(verification_code)
    db.commit()
    db.refresh(user)
    
    access_token = create_access_token(data={"sub": user.email, "scope": "access_token"})
    refresh_token = create_session(db, request, user)
    
    _set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        refresh_csrf_token=_new_csrf_token(),
    )
    
    response.delete_cookie(key="verification_token", path="/auth/verify-email")
    
    log_event(db, user_id=str(user.id), action="email_verified", category=LogCategory.AUTH, message="Email verified", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)
    
    return UserResponse.model_validate(user)


def login_user(db: Session, response: Response, request: Request, email: str, password: str) -> UserResponse:
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid credentials")
    
    if not user.is_verified:
        resend_code_service(db, response, request, user.email, VerificationPurpose.EMAIL_VERIFICATION)
        set_cookie_header = response.headers.get("set-cookie")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. A new verification code has been sent to your email.",
            headers={"set-cookie": set_cookie_header} if set_cookie_header else None
        )
    
    if is_account_locked(user):
        log_event(db, user_id=str(user.id), action="account_locked", category=LogCategory.AUTH, message="Account locked due to failed login attempts", level=LogLevel.WARNING, meta_data={"email": user.email}, request=request)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is locked due to multiple failed login attempts. Please try again later.")
    
    if not verify_password(password, user.password):
        handle_failed_login(user)
        db.add(user)
        db.commit()
        log_event(db, user_id=str(user.id), action="failed_login", category=LogCategory.AUTH, message="Failed login attempt", level=LogLevel.WARNING, meta_data={"email": user.email}, request=request)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    reset_login_attempts(user)
    user.last_login = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    refresh_token = create_session(db, request, user)
    access_token = create_access_token(data={"sub": user.email, "scope": "access_token"})
    
    _set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        refresh_csrf_token=_new_csrf_token(),
    )
    
    log_event(db, user_id=str(user.id), action="login_success", category=LogCategory.AUTH, message="User logged in", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)
    
    return UserResponse.model_validate(user)


def refresh_token_service(db: Session, request: Request, response: Response) -> MessageResponse:
    _validate_refresh_csrf(request)
    refresh_token = request.cookies.get("refresh_token")   
    
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    payload = decode_refresh_token(refresh_token)
    
    if not payload or payload.get("scope") != "refresh_token":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    sessions = db.exec(select(UserSession).where(UserSession.user_id == user.id)).all()
    session = next((s for s in sessions if verify_refresh_token(refresh_token, s.refresh_token)), None)

    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    if session.refresh_token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    if session.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    new_refresh_token = create_refresh_token(data={"sub": user.email, "scope": "refresh_token"})
    access_token = create_access_token(data={"sub": user.email, "scope": "access_token"})
    
    session.refresh_token = hash_refresh_token(new_refresh_token)
    session.refresh_token_expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS) 

    db.add(session)
    db.commit()

    _set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=new_refresh_token,
        refresh_csrf_token=_new_csrf_token(),
    )

    log_event(db, user_id=str(user.id), action="token_refreshed", category=LogCategory.AUTH, message="Token refreshed", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)  
    
    return MessageResponse(message="Token refreshed successfully")


def reset_password_service(db: Session, request: Request, email: str) -> MessageResponse:
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified")
    
    code = generate_verification_code()
    create_verification_code(db, user.id, code, VerificationPurpose.PASSWORD_RESET)
    send_password_reset_email(fullname=user.fullname, email=user.email, reset_code=code, expiry=settings.VERIFICATION_CODE_EXPIRY_MINUTES)
    
    log_event(db, user_id=str(user.id), action="password_reset_requested", category=LogCategory.AUTH, message="Password reset requested", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)
    
    return MessageResponse(message="Password reset code sent successfully")


def confirm_reset_password_service(data: PasswordResetSchema, password_reset_token: str, db: Session, request: Request) -> MessageResponse:
    payload = decode_verification_token(password_reset_token)
    if not payload or payload.get("scope") != "password_reset_token":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset token")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    codes = db.exec(select(VerificationCode).where(
        VerificationCode.user_id == user.id,
        VerificationCode.type == VerificationPurpose.PASSWORD_RESET,
        VerificationCode.used == False
    )).all()
    
    if not codes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid password reset code found")
    
    reset_code_entry = None
    for code_entry in codes:
        if code_entry.expires_at < datetime.now(timezone.utc):
            continue
        if verify_verification_code(data.code, code_entry.code):
            reset_code_entry = code_entry
            break

    if not reset_code_entry:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset code")
    
    user.password = hash_password(data.new_password)
    reset_code_entry.used = True
    reset_code_entry.used_at = datetime.now(timezone.utc)
    
    db.add(user)
    db.add(reset_code_entry)
    db.commit()
    db.refresh(user)
    
    log_event(db, user_id=str(user.id), action="password_reset_successful", category=LogCategory.AUTH, message="Password reset successful", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)
    
    return MessageResponse(message="Password reset successful")


def resend_code_service(db: Session, response: Response, request: Request, email: str, code_type: VerificationPurpose | str) -> MessageResponse:
    if isinstance(code_type, str):
        try:
            code_type = VerificationPurpose(code_type)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid code type")

    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    codes = db.exec(select(VerificationCode).where(
        VerificationCode.user_id == user.id,
        VerificationCode.type == code_type,
        VerificationCode.used == False
    )).all()

    RESEND_THRESHOLD_MINUTES = 2
    now = datetime.now(timezone.utc)

    valid_codes = [c for c in codes if c.expires_at > now]
    invalid_codes = [c for c in codes if c.expires_at < now]

    for invalid_code in invalid_codes:
        invalid_code.used = True
        db.add(invalid_code)
    db.commit()

    if valid_codes:
        latest_code = max(valid_codes, key=lambda c: c.created_at)
        created_at = latest_code.created_at
        created_at_utc = created_at.replace(tzinfo=timezone.utc) if created_at.tzinfo is None else created_at.astimezone(timezone.utc)
        time_since_created = now - created_at_utc

        if time_since_created < timedelta(minutes=RESEND_THRESHOLD_MINUTES):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please wait before resending the code")

        for code_entry in valid_codes:
            code_entry.used = True
            db.add(code_entry)
        db.commit()

    code = generate_verification_code()
    create_verification_code(db, user.id, code, code_type)

    if code_type == VerificationPurpose.EMAIL_VERIFICATION:
        send_verification_email(
            fullname=user.fullname,
            email=user.email,
            verification_code=code,
            expiry=settings.VERIFICATION_CODE_EXPIRY_MINUTES
        )
    elif code_type == VerificationPurpose.PASSWORD_RESET:
        send_password_reset_email(
            fullname=user.fullname,
            email=user.email,
            reset_code=code,
            expiry=settings.VERIFICATION_CODE_EXPIRY_MINUTES
        )

    if code_type == VerificationPurpose.EMAIL_VERIFICATION:
        verification_token = create_verification_token(
            data={"sub": user.email, "scope": "email_verification"}
        )
        response.set_cookie(
            key="verification_token",
            value=verification_token,
            httponly=True,
            max_age=1800,
            expires=1800,
            samesite="lax",
            secure=settings.ENVIRONMENT == "production",
            path="/auth/verify-email"
        )
    elif code_type == VerificationPurpose.PASSWORD_RESET:
        password_reset_token = create_verification_token(
            data={"sub": user.email, "scope": "password_reset_token"}
        )
        response.set_cookie(
            key="password_reset_token",
            value=password_reset_token,
            httponly=True,
            max_age=1800,
            expires=1800,
            samesite="lax",
            secure=settings.ENVIRONMENT == "production",
            path="/auth/confirm-reset-password"
        )

    log_event(db, user_id=str(user.id), action="code_resent", category=LogCategory.AUTH, message=f"{code_type.value.replace('_', ' ').title()} code resent", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)

    return MessageResponse(message="Verification code resent successfully")


def logout_service(db: Session, request: Request, response: Response) -> MessageResponse:
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token missing")
    
    payload = decode_refresh_token(refresh_token)
    
    if not payload or payload.get("scope") != "refresh_token":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    sessions = db.exec(select(UserSession).where(UserSession.user_id == user.id)).all()
    session = next((s for s in sessions if verify_refresh_token(refresh_token, s.refresh_token)), None)

    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    
    session.revoked = True
    session.revoked_at = datetime.now(timezone.utc)
    db.add(session)
    db.commit()
    
    _clear_auth_cookies(response)
    
    log_event(db, user_id=str(user.id), action="logout_success", category=LogCategory.AUTH, message="User logged out", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)
    
    return MessageResponse(message="Logged out successfully")


def logout_service_all(db: Session, request: Request, response: Response) -> MessageResponse:
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token missing")
    
    payload = decode_refresh_token(refresh_token)
    
    if not payload or payload.get("scope") != "refresh_token":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    sessions = db.exec(select(UserSession).where(UserSession.user_id == user.id)).all()
    session = next((s for s in sessions if verify_refresh_token(refresh_token, s.refresh_token)), None)

    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    
    for s in sessions:                                 
        s.revoked = True                               
        s.revoked_at = datetime.now(timezone.utc)
        db.add(s)
    db.commit()
    
    _clear_auth_cookies(response)
    
    log_event(db, user_id=str(user.id), action="logout_all_success", category=LogCategory.AUTH, message="User logged out from all sessions", level=LogLevel.INFO, meta_data={"email": user.email}, request=request)
    
    return MessageResponse(message="Logged out successfully")
