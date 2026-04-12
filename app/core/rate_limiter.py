from slowapi import Limiter
from slowapi.util import get_remote_address 

#decode token 
from app.core.security import decode_access_token

# JWT error
from jose import JWTError

def key_func(request):
    # 1. Get token from cookie
    token = request.cookies.get("access_token")

    if token:
        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")

            if user_id:
                return f"user:{user_id}"

        except JWTError:
            pass  

    # 2. Fallback to IP
    return f"ip:{request.client.host}"

limiter = Limiter(key_func=get_remote_address)
