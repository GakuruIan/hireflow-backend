from passlib.context import CryptContext
from datetime import datetime, timedelta,timezone
from jose import JWTError, jwt
from app.core.config import settings

#password hashing configuration
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def hash_verification_code(code: str) -> str:
    return pwd_context.hash(code)


def hash_refresh_token(refresh_token: str) -> str:
    return pwd_context.hash(refresh_token)

def verify_refresh_token(plain_refresh_token: str, hashed_refresh_token: str) -> bool:
    return pwd_context.verify(plain_refresh_token, hashed_refresh_token)

def verify_verification_code(plain_code: str, hashed_code: str) -> bool:
    return pwd_context.verify(plain_code, hashed_code)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode,settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode,settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_refresh_token(token: str):
    try:
        payload = jwt.decode(token, settings.REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None

def create_verification_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRY_MINUTES)
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(to_encode,settings.PENDING_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_verification_token(token: str):
    try:
        payload = jwt.decode(token, settings.PENDING_SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None