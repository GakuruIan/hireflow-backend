from fastapi import FastAPI
from fastapi.responses import JSONResponse

# routes
from app.auth.routes import router

# limiter
from app.core.rate_limiter import limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

app = FastAPI()

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

app.include_router(router)


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests, please try again later."},
    )
