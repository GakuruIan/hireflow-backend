from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """Application settings."""

    app_name: str = "Hireflow API"
    DATABASE_URL: str

    SECRET_KEY: str
    PENDING_SECRET_KEY:str
    REFRESH_SECRET_KEY:str
    ALGORITHM: str
    
    
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    REFRESH_TOKEN_EXPIRE_DAYS:int
    VERIFICATION_CODE_EXPIRY_MINUTES:int
    
    MAX_LOGIN_ATTEMPTS: int
    ACCOUNT_LOCK_MINUTES: int   


    EMAIL_HOST: str
    EMAIL_PORT: int
    EMAIL_USER: str
    EMAIL_PASS: str
    EMAIL_FROM: str

    REDIS_HOST: str 
    REDIS_PORT: int 

    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"


settings = Settings()