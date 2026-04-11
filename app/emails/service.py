from .workers import email_queue

    
def send_verification_email(fullname, email, verification_code, expiry):
    email_queue.enqueue("app.emails.workers.send_verification_email_task", fullname, email, verification_code, expiry)
    
def send_password_reset_email(fullname, email, reset_code, expiry):
    email_queue.enqueue("app.emails.workers.send_password_reset_email_task", fullname, email, reset_code, expiry)