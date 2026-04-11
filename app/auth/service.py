from sqlmodel import Session, select
from fastapi import HTTPException,status,Response,Request
# models
from app.db.models import User, VerificationCode ,VerificationPurpose,Session as UserSession
# security
from app.core.security import hash_password,decode_verification_token,hash_verification_code,verify_verification_code ,verify_password ,create_refresh_token,hash_refresh_token,create_access_token,decode_refresh_token,verify_refresh_token,create_verification_token

# schemas
from app.auth.schema import RegisterSchema,  UserResponse,PasswordResetSchema,MessageResponse

# utils functions
from app.utils.code import generate_verification_code
from app.utils.client_info import get_client_info
from app.utils.helpers import is_account_locked, handle_failed_login, reset_login_attempts

# email service
from app.emails.service import send_verification_email,send_password_reset_email

# settings
from app.core.config import settings

# datetime
from datetime import datetime, timezone,timedelta

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

def create_session(db: Session,request:Request ,user:dict):
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

def register_user(db: Session, register_data: RegisterSchema) -> UserResponse:
    existing_user = get_user_by_email(db, register_data.email)

    if existing_user:
       raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    new_user = User(
        fullname=register_data.fullname,
        email=register_data.email,
        password=hash_password(register_data.password),
        is_verified=False,
        failed_login_attempts=0
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    code = generate_verification_code()
    
    create_verification_code(db, new_user.id, code, VerificationPurpose.EMAIL_VERIFICATION)
    
    
   
    send_verification_email(fullname=new_user.fullname, email=new_user.email, verification_code=code, expiry=settings.VERIFICATION_CODE_EXPIRY_MINUTES)
    return UserResponse.model_validate(new_user)

#implement verify email function
def verify_email_service(db: Session,  response:Response,request: Request,code: str,verification_token: str)-> UserResponse:
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
        VerificationCode.user_id == user.id, VerificationCode.type == VerificationPurpose.EMAIL_VERIFICATION,VerificationCode.used == False)).all()
    
    verification_code = None
    
    if not codes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid verification code found")
    
    for code_entry in codes:
        if code_entry.expires_at < datetime.now(timezone.utc):
            continue  # Skip expired codes
        
        if verify_verification_code(code, code_entry.code):
            verification_code = code_entry
            break
    if not verification_code:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification code")
    
    user.is_verified=True
    user.verified_at = datetime.now(timezone.utc)
    verification_code.used = True
    verification_code.used_at = datetime.now(timezone.utc)
    
    db.add(user)
    db.add(verification_code)
    db.commit()
    db.refresh(user)
    
    access_token = create_access_token(data={"sub": user.email, "scope": "access_token"})
    
    refresh_token = create_session(db, request,user)
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age="3600",  # 1 hour in seconds
        expires="3600",
        samesite="lax",
        secure=settings.ENVIRONMENT == "production"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=7*24*3600,  # 7 days in seconds
        expires=7*24*3600,
        samesite="lax",
        path="/auth/refresh-token",
        secure=settings.ENVIRONMENT == "production"
    )
    
    response.delete_cookie(key="verification_token", path="/auth/verify-email")
    
    
    return UserResponse.model_validate(user)


def login_user(db: Session,response:Response,request:Request ,email: str, password: str) -> UserResponse:
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid credentials")
    
    if not user.is_verified:
        resend_code_service(db, response, user.email, VerificationPurpose.EMAIL_VERIFICATION)
       
        set_cookie_header = response.headers.get("set-cookie")

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. A new verification code has been sent to your email.",
            headers={"set-cookie": set_cookie_header} if set_cookie_header else None
        )
    
    if is_account_locked(user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is locked due to multiple failed login attempts. Please try again later.")
    
    if not verify_password(password, user.password):
        handle_failed_login(user)
        db.add(user)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    reset_login_attempts(user)
    user.last_login = datetime.now(timezone.utc)
    user.failed_login_attempts = 0
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    
    refresh_token = create_session(db, request,user)

    access_token = create_access_token(data={"sub": user.email, "scope": "access_token"})
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=3600,  # 1 hour in seconds
        expires=3600,
        samesite="lax",
        path="/",
        secure=settings.ENVIRONMENT == "production"
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=7*24*3600,  # 7 days in seconds
        expires=7*24*3600,
        samesite="lax",
        path="/auth/refresh-token",
        secure=settings.ENVIRONMENT == "production"
    )
    
    
    return UserResponse.model_validate(user)

def refresh_token_service(db: Session, refresh_token: str, response: Response) ->MessageResponse:
    
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token missing")
    
    payload = decode_refresh_token(refresh_token)
    
    if not payload or payload.get("scope") != "refresh_token":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified")  

    
    sessions = db.exec(select(UserSession).where(UserSession.user_id == user.id)).all()


    session = next((s for s in sessions if verify_refresh_token(refresh_token, s.refresh_token)),None)

    
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    
    if session.refresh_token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # add revoke checking


    new_refresh_token =  create_refresh_token(data={"sub": user.email, "scope": "refresh_token"})
    access_token = create_access_token(data={"sub": user.email, "scope": "access_token"})
    session.refresh_token = hash_refresh_token(new_refresh_token)
    session.refresh_token_expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    db.add(session)
    db.commit()
    
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=3600,  # 1 hour in seconds
        expires=3600,
        samesite="lax",
        path="/",
        secure=settings.ENVIRONMENT == "production"
    )

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        max_age=7*24*3600,  # 7 days in seconds
        expires=7*24*3600,
        samesite="lax",
        path="/auth/refresh-token",
        secure=settings.ENVIRONMENT == "production"
    )
    
    return MessageResponse(message="Token refreshed successfully")
    
    

def reset_password_service(db: Session, email: str)-> UserResponse:
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email not verified")
    
    code = generate_verification_code()
    
    create_verification_code(db, user.id, code, VerificationPurpose.PASSWORD_RESET)
    
    send_password_reset_email(fullname=user.fullname, email=user.email, reset_code=code, expiry=settings.VERIFICATION_CODE_EXPIRY_MINUTES)
    
    return UserResponse.model_validate(user)

def confirm_reset_password_service(data: PasswordResetSchema, password_reset_token: str, db: Session) -> MessageResponse:
    payload = decode_verification_token(password_reset_token)
    if not payload or payload.get("scope") != "password_reset_token":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired password reset token")
    
    email = payload.get("sub")
    user = get_user_by_email(db, email)
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    codes = db.exec(select(VerificationCode).where(
        VerificationCode.user_id == user.id, VerificationCode.type == VerificationPurpose.PASSWORD_RESET,VerificationCode.used == False)).all()
    
    reset_code_entry = None
    
    if not codes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No valid password reset code found")
    
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
    
    return MessageResponse(message="Password reset successful")

def resend_code_service(db: Session, response:Response,email: str, code_type: VerificationPurpose | str) -> MessageResponse:
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

    # if not codes:
    #     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No valid code found")

    RESEND_THRESHOLD_MINUTES = 2
    now = datetime.now(timezone.utc)

    valid_codes = [c for c in codes if c.expires_at >now]
    invalid_codes = [c for c in codes if c.expires_at <now]


    # invalidate all previous codes
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

    # issue verification token
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


    return MessageResponse(message="Verification code resent successfully")
    
    
        
