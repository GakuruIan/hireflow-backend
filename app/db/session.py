from sqlmodel import SQLModel, create_engine, Session
from app.core.config import settings

engine = create_engine(settings.DATABASE_URL,echo=True) # disable echo in production

def get_session():
    with Session(engine) as session:
        yield session #FastAPI auto closes connection after request

