from fastapi import Request
from user_agents import parse as parse_user_agent
from typing import TypedDict, Optional


class ClientInfo(TypedDict):
    device: str
    os: str
    browser: str
    ip_address: str

    
def get_client_info(request: Request):
    forwarded_for = request.headers.get('X-Forwarded-For')
    
    if forwarded_for:
        ip_address = forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.client.host
        
    raw_user_agent = request.headers.get('User-Agent', 'unknown')
    
    ua = parse_user_agent(raw_user_agent)
    
    if ua.is_mobile:
        device = 'Mobile'
    elif ua.is_tablet:
        device = 'Tablet'
    elif ua.is_pc:
        device = 'Desktop'
    elif ua.is_bot:
        device = 'Bot'
    else:
        device = 'Unknown'
    
    return {
        "ip_address": ip_address,
        "user_agent": raw_user_agent,
        "device_name": device,
        "browser": f"{ua.browser.family} {ua.browser.version_string}",
        "os": f"{ua.os.family} {ua.os.version_string}",
    }