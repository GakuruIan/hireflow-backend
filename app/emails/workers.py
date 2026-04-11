from redis import Redis
from rq import Queue
from app.core.config import settings
from .templates import render_verfication_email, render_password_reset_email
from .smtp import send_email_smtp

redis_conn = Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT, db=0)
email_queue = Queue('emails', connection=redis_conn)

def send_verification_email_task(fullname, email, verification_code, expiry):
    html_content = render_verfication_email(fullname, verification_code, expiry)
    send_email_smtp(to_email=email, subject="Email Verification", html_content=html_content)
    
def send_password_reset_email_task(fullname, email, reset_code, expiry):
    html_content = render_password_reset_email(fullname, reset_code, expiry)
    send_email_smtp(to_email=email, subject="Password Reset Request", html_content=html_content)