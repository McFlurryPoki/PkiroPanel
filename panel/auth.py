"""Authentication — token creation, verification, and FastAPI dependency."""

import os
import time
import json
import hmac
import hashlib
import base64
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
TOKEN_TTL = 86400 * 7  # 7 days

security = HTTPBearer(auto_error=False)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_token(user_id: int, username: str, role: str) -> str:
    """Create a signed token for the user."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({
        "sub": user_id,
        "usr": username,
        "rol": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_TTL,
    }).encode())
    signing_input = f"{header}.{payload}"
    sig = _b64url_encode(
        hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
    )
    return f"{signing_input}.{sig}"


def verify_token(token: str) -> dict | None:
    """Verify and decode a token. Returns payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        signing_input = f"{header}.{payload}"
        expected_sig = _b64url_encode(
            hmac.new(SECRET_KEY.encode(), signing_input.encode(), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(sig, expected_sig):
            return None
        data = json.loads(_b64url_decode(payload))
        if data.get("exp", 0) < time.time():
            return None
        return data
    except Exception:
        return None


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict:
    """FastAPI dependency — extracts current user from token."""
    token = None
    if credentials:
        token = credentials.credentials
    elif "Authorization" in request.headers:
        auth = request.headers["Authorization"]
        if auth.startswith("Bearer "):
            token = auth[7:]

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return {
        "id": payload["sub"],
        "username": payload["usr"],
        "role": payload["rol"],
    }


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Require admin role."""
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user
