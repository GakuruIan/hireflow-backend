from pydantic import BaseModel, EmailStr,ConfigDict
from datetime import datetime
from uuid import UUID


class RegisterSchema(BaseModel):
    fullname:str
    email: EmailStr
    password: str
    role:str
    
class LoginSchema(BaseModel):
    email: EmailStr
    password: str
    
    
class VerifyEmailSchema(BaseModel):
    verification_code: str

class UserResponse(BaseModel):
    id: UUID
    fullname: str
    email: EmailStr
    is_verified: bool  
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
        
class MessageResponse(BaseModel):
    message: str
    
class LoginResponse(BaseModel):
    user: UserResponse
    message: str
    
class PasswordResetSchema(BaseModel):
    code:str
    new_password:str
    