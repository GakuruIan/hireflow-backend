from jinja2 import Environment, FileSystemLoader
from pathlib import Path

TEMPLATE_DIR = Path(__file__).parent / 'templates'
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))


def render_verfication_email(fullname, verification_code,expiry: int):
    template = env.get_template('email-verification-template.html')
    
    return template.render(
       {
        "fullname": fullname,
        "verificationCode": verification_code,
        "expiryMinutes": expiry,
        "year": 2026
       }
    )
    
    
def render_password_reset_email(fullname, reset_code, expiry: int):
    template = env.get_template('password-reset-template.html')
    
    return template.render(
       {
        "fullname": fullname,
        "resetCode": reset_code,
        "expiryMinutes": expiry,
        "year": 2026
       }
    )