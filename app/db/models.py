from sqlmodel import SQLModel , Field ,Column,DateTime
from typing import Optional
from datetime import datetime,timezone,timedelta
from uuid import UUID,uuid4
from enum import Enum
from app.core.config import settings

class VerificationPurpose(str, Enum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"

class User(SQLModel, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    fullname: str=Field(index=True)
    email: str=Field(index=True, unique=True)
    password: str
    is_verified: bool = Field(default=False)

    # account timestamps
    locked_until: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    last_login: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    verified_at: Optional[datetime] = Field(default=None, sa_column=Column(DateTime(timezone=True), nullable=True))
    
    #account lockout fields
    failed_login_attempts: int = Field(default=0)
    #account timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False, onupdate=datetime.now)
    )
    

class VerificationCode(SQLModel, table=True):
    __tablename__ = "verification_codes"
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id",index=True,nullable=False)
    code: str = Field(index=True, unique=True)
    type: VerificationPurpose = Field(index=True)
    used: bool = Field(default=False)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=settings.VERIFICATION_CODE_EXPIRY_MINUTES),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    used_at: Optional[datetime] = Field(
        default=None,
        sa_column=Column(DateTime(timezone=True), nullable=True)
    )


class Session(SQLModel,table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    user_id: UUID = Field(foreign_key="user.id", index=True, nullable=False)
    refresh_token: str= Field(index=True, unique=True, default=None)
    
    device_name: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    os: Optional[str] = None
    browser: Optional[str] = None
    
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )
    refresh_token_expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        sa_column=Column(DateTime(timezone=True), nullable=False)
    )