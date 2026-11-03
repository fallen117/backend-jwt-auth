from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import AfterValidator, BaseModel, EmailStr, Field


# ---------- Validadores ----------
def _max_72_bytes(v: str) -> str:
    # bcrypt solo procesa los primeros 72 bytes
    if len(v.encode("utf-8")) > 72:
        raise ValueError("La contraseña no puede superar 72 bytes")
    return v


def _strong_password(v: str) -> str:
    _max_72_bytes(v)
    if not (any(c.islower() for c in v) and any(c.isupper() for c in v) and any(c.isdigit() for c in v)):
        raise ValueError("La contraseña debe incluir mayúsculas, minúsculas y números")
    return v


LoginPassword = Annotated[str, Field(min_length=1, max_length=72), AfterValidator(_max_72_bytes)]
NewPassword = Annotated[str, Field(min_length=8, max_length=72), AfterValidator(_strong_password)]
Username = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{3,30}$")]
RoleName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,49}$")]


# ---------- Auth ----------
class RegisterRequest(BaseModel):
    email: EmailStr
    username: Username
    password: NewPassword
    full_name: str | None = Field(default=None, max_length=120)


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=255, description="Email o username")
    password: LoginPassword


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="Segundos de vigencia del access token")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=512)


class LogoutRequest(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=512)


class ChangePasswordRequest(BaseModel):
    current_password: LoginPassword
    new_password: NewPassword


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=20, max_length=512)
    new_password: NewPassword


class MessageResponse(BaseModel):
    message: str
    debug_token: str | None = None  # solo si EXPOSE_DEBUG_TOKENS=true


# ---------- Usuarios ----------
class UserOut(BaseModel):
    id: UUID
    email: str
    username: str
    full_name: str | None = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    last_login_at: datetime | None = None
    created_at: datetime


class UserWithRoles(UserOut):
    roles: list[str] = []


class MeOut(UserOut):
    roles: list[str]
    permissions: list[str]


class UserCreate(BaseModel):
    email: EmailStr
    username: Username
    password: NewPassword
    full_name: str | None = Field(default=None, max_length=120)
    is_verified: bool = True
    roles: list[RoleName] = Field(default_factory=list, description="Si se omite, se asigna el rol por defecto")


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    username: Username | None = None
    full_name: str | None = Field(default=None, max_length=120)
    is_active: bool | None = None
    is_verified: bool | None = None


class SetRolesRequest(BaseModel):
    roles: list[RoleName]


# ---------- Roles / permisos ----------
class PermissionOut(BaseModel):
    id: UUID
    code: str
    resource: str
    action: str
    description: str | None = None


class RoleOut(BaseModel):
    id: UUID
    name: str
    description: str | None = None
    is_system: bool
    permissions: list[str] = []


class RoleCreate(BaseModel):
    name: RoleName
    description: str | None = Field(default=None, max_length=255)
    permissions: list[str] = Field(default_factory=list)


class SetPermissionsRequest(BaseModel):
    permissions: list[str]


# ---------- Auditoría ----------
class AuditOut(BaseModel):
    id: int
    user_id: UUID | None = None
    event_type: str
    success: bool
    ip_address: str | None = None
    user_agent: str | None = None
    details: dict[str, Any] = {}
    created_at: datetime
