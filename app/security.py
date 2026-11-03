"""Hash de contraseñas (bcrypt) y emisión/validación de JWT."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import bcrypt
import jwt

from .config import settings


# ---------- Contraseñas ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# Hash ficticio para igualar tiempos de respuesta cuando el usuario no existe (anti-enumeración por timing)
DUMMY_HASH = hash_password("dummy-password-for-timing")


# ---------- Tokens opacos (refresh, verificación, reset) ----------
def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """SHA-256 hex. Es lo que se guarda en la BD; el token en claro nunca se almacena."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------- Access token (JWT) ----------
def create_access_token(
    user_id: UUID, roles: list[str], permissions: list[str], token_version: int
) -> tuple[str, UUID, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_expire_minutes)
    jti = uuid4()
    payload = {
        "sub": str(user_id),
        "jti": str(jti),
        "iss": settings.jwt_issuer,
        "iat": now,
        "exp": expires_at,
        "type": "access",
        "ver": token_version,
        "roles": roles,
        "perms": permissions,
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti, expires_at


def decode_access_token(token: str) -> dict:
    """Lanza jwt.ExpiredSignatureError / jwt.PyJWTError si el token no es válido."""
    return jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "jti", "iss"]},
        leeway=10,
    )
