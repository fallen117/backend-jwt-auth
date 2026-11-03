"""Dependencias de FastAPI: autenticación (JWT) y autorización (roles / permisos)."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import jwt
import psycopg
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer

from . import repository as repo
from .database import get_conn
from .security import decode_access_token

# tokenUrl apunta al endpoint de formulario para que el botón "Authorize" de Swagger funcione
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


@dataclass
class CurrentUser:
    id: UUID
    email: str
    username: str
    full_name: str | None
    is_superuser: bool
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    jti: UUID | None = None
    token_exp: datetime | None = None

    def has_permission(self, code: str) -> bool:
        return self.is_superuser or code in self.permissions


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def get_current_user(
    token: str = Depends(oauth2_scheme), conn: psycopg.Connection = Depends(get_conn)
) -> CurrentUser:
    # 1) Firma, expiración, issuer y claims obligatorios
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expirado")
    except jwt.PyJWTError:
        raise _unauthorized("Token inválido")

    if payload.get("type") != "access":
        raise _unauthorized("Tipo de token inválido")

    try:
        user_id = UUID(payload["sub"])
        jti = UUID(payload["jti"])
    except (ValueError, KeyError):
        raise _unauthorized("Token inválido")

    # 2) Revocación explícita (logout)
    if repo.is_blacklisted(conn, jti):
        raise _unauthorized("Token revocado")

    # 3) Usuario vigente y versión de token (cambio de contraseña / logout-all)
    user = repo.get_user_by_id(conn, user_id)
    if user is None or not user["is_active"]:
        raise _unauthorized("Usuario inexistente o inactivo")
    if payload.get("ver") != user["token_version"]:
        raise _unauthorized("Token revocado")

    # 4) Roles y permisos tomados de la BD (los cambios aplican de inmediato, sin esperar al refresh)
    return CurrentUser(
        id=user["id"],
        email=user["email"],
        username=user["username"],
        full_name=user["full_name"],
        is_superuser=user["is_superuser"],
        roles=repo.get_user_roles(conn, user["id"]),
        permissions=repo.get_user_permissions(conn, user["id"], user["is_superuser"]),
        jti=jti,
        token_exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
    )


def require_permissions(*codes: str):
    """Exige TODOS los permisos indicados (el superusuario siempre pasa)."""

    def checker(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        missing = [c for c in codes if not current.has_permission(c)]
        if missing:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Permisos insuficientes: {', '.join(missing)}")
        return current

    return checker


def require_roles(*names: str):
    """Exige AL MENOS UNO de los roles indicados (el superusuario siempre pasa)."""

    def checker(current: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not current.is_superuser and not set(names) & set(current.roles):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Se requiere uno de los roles: {', '.join(names)}")
        return current

    return checker


def client_info(request: Request) -> tuple[str | None, str | None]:
    """IP y User-Agent del cliente. Si hay proxy inverso, configura uvicorn con --proxy-headers."""
    ip = request.client.host if request.client else None
    return ip, request.headers.get("user-agent")
