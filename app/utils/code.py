import random


def generate_verification_code(length: int = 6) -> str:
    """Generates a random numeric verification code of specified length."""
    return ''.join(random.choices('0123456789', k=length))