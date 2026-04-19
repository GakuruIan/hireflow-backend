from fastapi import APIRouter, Depends,Response,Cookie,HTTPException,status ,Request
# services
from app.auth.service import register_user,verify_email_service,login_user ,reset_password_service, confirm_reset_password_service,refresh_token_service,resend_code_service, logout_service, logout_service_all

# scheams
from app.auth.schema import RegisterSchema,MessageResponse,VerifyEmailSchema,LoginResponse,LoginSchema,PasswordResetSchema

# security
from app.core.security import create_access_token,create_verification_token

# seesion control
from app.db.session import get_session

# settings
from app.core.config import settings

# models
from app.db.models import VerificationPurpose

from app.core.rate_limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=MessageResponse)
@limiter.limit("3/minute")
def register(payload:RegisterSchema,response:Response,request:Request,db= Depends(get_session)):
    user = register_user(db, request, payload)
    verification_token = create_verification_token(data={"sub": user.email,"scope":"email_verification"})
    
    response.set_cookie(
        key="verification_token",
        value=verification_token,
        httponly=True,
        max_age="1800",  # 30 minutes in seconds
        expires="1800",
        samesite="lax",
        secure=settings.ENVIRONMENT == "production",
        path="/auth/verify-email"
    )
    
    return {"message": "Please check your email for the verification code"}

@limiter.limit("10/minute")
@router.post("/verify-email",response_model=LoginResponse)
def verify_email(payload: VerifyEmailSchema, verification_token: str = Cookie(None), response: Response = None,request: Request = None, db=Depends(get_session)):
    
    if not verification_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification token missing")
    
    user = verify_email_service(db, response, request, payload.verification_code, verification_token)
    
    return {"user": user, "message": "Email verified successfully"}
    
@router.post("/login", response_model=LoginResponse) 
@limiter.limit("5/minute")
def login(payload: LoginSchema, response: Response, request: Request, db=Depends(get_session)) -> LoginResponse:
    user = login_user(db, response, request, payload.email, payload.password)
    return {"user": user, "message": "Login successful"}

@router.post("/reset-password",response_model=MessageResponse)
@limiter.limit("3/minute")
def reset_password(email: str, response: Response, request: Request,db=Depends(get_session)):
    reset_password_service(db, request, email)
    
    password_reset_token = create_verification_token(data={"sub": email, "scope": "password_reset_token"})
    
    response.set_cookie(
        key="password_reset_token",
        value=password_reset_token,
        httponly=True,
        max_age="1800", 
        expires="1800",
        samesite="lax",
        secure=settings.ENVIRONMENT == "production"
    )
    
    return {"message": "Password reset email sent"}

@router.post("/confirm-reset-password",response_model=MessageResponse)
@limiter.limit("5/minute")
def confirm_reset_password(data: PasswordResetSchema, password_reset_token: str = Cookie(None), response: Response = None,request: Request = None, db=Depends(get_session)):
    message = confirm_reset_password_service(data, password_reset_token, db, request)
    
    response.delete_cookie(key="password_reset_token")
    return message


@router.post("/refresh-token", response_model=MessageResponse)
@limiter.limit("20/minute")
def refresh_token(response: Response, request: Request, db=Depends(get_session)):
    message = refresh_token_service(db, request, response)
    return message
    
@router.post("/resend-code",response_model=MessageResponse)
@limiter.limit("3/minute")
def resend_code(email: str, code_type: VerificationPurpose, response: Response, request: Request = None,db=Depends(get_session)):
    message = resend_code_service(db, response, request, email, code_type)
    return message


@router.post("/logout", response_model=MessageResponse)
@limiter.limit("10/minute")
def logout(response: Response, request: Request,db=Depends(get_session)):
    message = logout_service(db,request,response)
    return message

@router.post("/logout-all", response_model=MessageResponse)
@limiter.limit("30/minute")
def logout_all(response: Response, request: Request,db=Depends(get_session)):
    message = logout_service_all(db,request,response)
    return message
