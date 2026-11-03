"""Lógica de negocio de autenticación. Opera sobre las tablas jwt_*."""
import logging
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import psycopg
from fastapi import HTTPException, status

from . import repository as repo
from .config import settings
from .schemas import RegisterRequest, TokenResponse
from .security import (
    DUMMY_HASH,
    create_access_token,
    hash_password,
    hash_token,
    new_opaque_token,
    verify_password,
)

logger = logging.getLogger("backend_jwt.auth")
Conn = psycopg.Connection


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _unauthorized(detail: str = "Credenciales inválidas") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def _send_email_stub(to: str, subject: str, token: str) -> None:
    """Punto de integración con tu proveedor de email (SMTP, SendGrid, SES...). Aquí solo se registra el envío."""
    logger.info("Email a %s: %s", to, subject)
    if settings.expose_debug_tokens:
        logger.info("  [debug] token: %s", token)


# =====================================================================
# Emisión de tokens
# =====================================================================
def issue_token_pair(
    conn: Conn, user: dict, ip: str | None, ua: str | None, family_id: UUID | None = None
) -> tuple[TokenResponse, UUID]:
    """Crea access token (JWT) + refresh token opaco y guarda el hash del refresh en jwt_refresh_tokens."""
    roles = repo.get_user_roles(conn, user["id"])
    perms = repo.get_user_permissions(conn, user["id"], user["is_superuser"])
    access, _jti, _exp = create_access_token(user["id"], roles, perms, user["token_version"])

    refresh_plain = new_opaque_token()
    row = repo.insert_refresh_token(
        conn,
        user_id=user["id"],
        jti=uuid4(),
        token_hash=hash_token(refresh_plain),
        family_id=family_id or uuid4(),
        expires_at=_now() + timedelta(days=settings.refresh_token_expire_days),
        ip=ip,
        user_agent=ua,
    )
    response = TokenResponse(
        access_token=access,
        refresh_token=refresh_plain,
        expires_in=settings.access_token_expire_minutes * 60,
    )
    return response, row["id"]


# =====================================================================
# Login
# =====================================================================
def authenticate(conn: Conn, identifier: str, password: str, ip: str | None, ua: str | None) -> TokenResponse:
    user = repo.get_user_by_identifier(conn, identifier)

    if user is None:
        verify_password(password, DUMMY_HASH)  # iguala tiempos de respuesta
        repo.insert_audit(conn, None, "login_failed", False, ip, ua,
                          {"identifier": identifier[:100], "reason": "unknown_user"})
        conn.commit()
        raise _unauthorized()

    if user["locked_until"] and user["locked_until"] > _now():
        repo.insert_audit(conn, user["id"], "login_blocked", False, ip, ua, {"reason": "account_locked"})
        conn.commit()
        raise HTTPException(
            status.HTTP_423_LOCKED,
            detail="Cuenta bloqueada temporalmente por demasiados intentos fallidos. Intenta más tarde.",
        )

    if not verify_password(password, user["password_hash"]):
        res = repo.register_failed_login(conn, user["id"], settings.max_failed_login_attempts, settings.lockout_minutes)
        repo.insert_audit(conn, user["id"], "login_failed", False, ip, ua,
                          {"reason": "bad_password", "attempts": res["failed_login_attempts"]})
        conn.commit()
        raise _unauthorized()

    if not user["is_active"]:
        repo.insert_audit(conn, user["id"], "login_failed", False, ip, ua, {"reason": "inactive"})
        conn.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Usuario inactivo")

    if settings.require_verified_email and not user["is_verified"]:
        repo.insert_audit(conn, user["id"], "login_failed", False, ip, ua, {"reason": "unverified"})
        conn.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Debes verificar tu email antes de iniciar sesión")

    repo.mark_login_success(conn, user["id"])
    tokens, _ = issue_token_pair(conn, user, ip, ua)
    repo.insert_audit(conn, user["id"], "login_success", True, ip, ua, {})
    return tokens


# =====================================================================
# Refresh con rotación y detección de reuso
# =====================================================================
def refresh_tokens(conn: Conn, refresh_token: str, ip: str | None, ua: str | None) -> TokenResponse:
    row = repo.get_refresh_token_for_update(conn, hash_token(refresh_token))
    if row is None:
        raise _unauthorized("Refresh token inválido")

    if row["revoked_at"] is not None:
        if row["revoked_reason"] == "rotated":
            # Un token ya rotado se volvió a presentar: posible robo. Se revoca toda la familia (sesión).
            repo.revoke_family(conn, row["family_id"], "reuse_detected")
            repo.insert_audit(conn, row["user_id"], "refresh_reuse_detected", False, ip, ua,
                              {"family_id": str(row["family_id"])})
            conn.commit()
        raise _unauthorized("Refresh token revocado")

    if row["expires_at"] <= _now():
        raise _unauthorized("Refresh token expirado")

    user = repo.get_user_by_id(conn, row["user_id"])
    if user is None or not user["is_active"]:
        raise _unauthorized("Usuario inexistente o inactivo")

    tokens, new_id = issue_token_pair(conn, user, ip, ua, family_id=row["family_id"])
    repo.revoke_refresh_token(conn, row["id"], "rotated", replaced_by=new_id)
    repo.insert_audit(conn, user["id"], "token_refresh", True, ip, ua, {})
    return tokens


# =====================================================================
# Logout
# =====================================================================
def logout(
    conn: Conn,
    user_id: UUID,
    access_jti: UUID | None,
    access_exp: datetime | None,
    refresh_token: str | None,
    ip: str | None,
    ua: str | None,
) -> None:
    if access_jti and access_exp:
        repo.blacklist_token(conn, access_jti, user_id, "access", "logout", access_exp)
    if refresh_token:
        row = repo.get_refresh_token_for_update(conn, hash_token(refresh_token))
        if row and row["user_id"] == user_id:
            repo.revoke_family(conn, row["family_id"], "logout")
    repo.insert_audit(conn, user_id, "logout", True, ip, ua, {})


def logout_all(conn: Conn, user_id: UUID, ip: str | None, ua: str | None) -> None:
    repo.revoke_all_user_refresh_tokens(conn, user_id, "logout_all")
    repo.bump_token_version(conn, user_id)  # invalida todos los access tokens emitidos
    repo.insert_audit(conn, user_id, "logout_all", True, ip, ua, {})


# =====================================================================
# Registro, verificación y contraseñas
# =====================================================================
def register_user(conn: Conn, data: RegisterRequest, ip: str | None, ua: str | None) -> tuple[dict, str]:
    if not settings.allow_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="El registro está deshabilitado")
    if repo.user_exists(conn, data.email, data.username):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="El email o el username ya están registrados")

    user = repo.create_user(conn, data.email, data.username, hash_password(data.password), data.full_name, False)
    repo.assign_role_by_name(conn, user["id"], settings.default_role)

    token = new_opaque_token()
    repo.create_verification_token(
        conn, user["id"], "email_verification", hash_token(token),
        _now() + timedelta(hours=settings.verification_token_expire_hours),
    )
    repo.insert_audit(conn, user["id"], "register", True, ip, ua, {})
    _send_email_stub(user["email"], "Verifica tu email", token)
    return user, token


def verify_email(conn: Conn, token: str, ip: str | None, ua: str | None) -> None:
    row = repo.get_verification_token_for_update(conn, hash_token(token), "email_verification")
    if row is None or row["used_at"] is not None or row["expires_at"] <= _now():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Token inválido o expirado")
    repo.mark_verified(conn, row["user_id"])
    repo.mark_verification_token_used(conn, row["id"])
    repo.insert_audit(conn, row["user_id"], "email_verified", True, ip, ua, {})


def change_password(
    conn: Conn, user_id: UUID, current_password: str, new_password: str, ip: str | None, ua: str | None
) -> None:
    user = repo.get_user_by_id(conn, user_id)
    if user is None or not verify_password(current_password, user["password_hash"]):
        repo.insert_audit(conn, user_id, "password_change_failed", False, ip, ua, {})
        conn.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="La contraseña actual es incorrecta")
    repo.set_password(conn, user_id, hash_password(new_password))
    repo.revoke_all_user_refresh_tokens(conn, user_id, "password_changed")
    repo.insert_audit(conn, user_id, "password_changed", True, ip, ua, {})


def forgot_password(conn: Conn, email: str, ip: str | None, ua: str | None) -> str | None:
    """Siempre responde igual al cliente (no revela si el email existe). Devuelve el token solo para modo debug."""
    user = repo.get_user_by_email(conn, email)
    if user is None or not user["is_active"]:
        return None
    token = new_opaque_token()
    repo.create_verification_token(
        conn, user["id"], "password_reset", hash_token(token),
        _now() + timedelta(minutes=settings.password_reset_expire_minutes),
    )
    repo.insert_audit(conn, user["id"], "password_reset_requested", True, ip, ua, {})
    _send_email_stub(user["email"], "Restablece tu contraseña", token)
    return token


def reset_password(conn: Conn, token: str, new_password: str, ip: str | None, ua: str | None) -> None:
    row = repo.get_verification_token_for_update(conn, hash_token(token), "password_reset")
    if row is None or row["used_at"] is not None or row["expires_at"] <= _now():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Token inválido o expirado")
    repo.set_password(conn, row["user_id"], hash_password(new_password))
    repo.revoke_all_user_refresh_tokens(conn, row["user_id"], "password_reset")
    repo.mark_verification_token_used(conn, row["id"])
    repo.insert_audit(conn, row["user_id"], "password_reset_done", True, ip, ua, {})
