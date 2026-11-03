import psycopg
from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from .. import repository as repo
from .. import services
from ..config import settings
from ..database import get_conn
from ..dependencies import CurrentUser, client_info, get_current_user
from ..schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    MeOut,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserOut,
    VerifyEmailRequest,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)):
    ip, ua = client_info(request)
    _user, token = services.register_user(conn, body, ip, ua)
    return MessageResponse(
        message="Usuario registrado. Revisa tu email para verificar la cuenta.",
        debug_token=token if settings.expose_debug_tokens else None,
    )


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)):
    ip, ua = client_info(request)
    return services.authenticate(conn, body.identifier, body.password, ip, ua)


@router.post("/token", response_model=TokenResponse, include_in_schema=True, summary="Login con formulario (Swagger)")
def login_form(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Mismo login que `/auth/login` pero con formulario OAuth2; lo usa el botón *Authorize* de Swagger.
    En `username` puedes poner email o username."""
    ip, ua = client_info(request)
    return services.authenticate(conn, form.username, form.password, ip, ua)


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)):
    ip, ua = client_info(request)
    return services.refresh_tokens(conn, body.refresh_token, ip, ua)


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    body: LogoutRequest | None = None,
    current: CurrentUser = Depends(get_current_user),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Revoca el access token actual (blacklist por `jti`) y, si se envía, la sesión del refresh token."""
    ip, ua = client_info(request)
    services.logout(
        conn, current.id, current.jti, current.token_exp, body.refresh_token if body else None, ip, ua
    )
    return MessageResponse(message="Sesión cerrada")


@router.post("/logout-all", response_model=MessageResponse)
def logout_all(
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Cierra todas las sesiones del usuario en todos los dispositivos."""
    ip, ua = client_info(request)
    services.logout_all(conn, current.id, ip, ua)
    return MessageResponse(message="Todas las sesiones fueron cerradas")


@router.get("/me", response_model=MeOut)
def me(current: CurrentUser = Depends(get_current_user), conn: psycopg.Connection = Depends(get_conn)):
    user = repo.get_user_by_id(conn, current.id)
    return {**user, "roles": current.roles, "permissions": current.permissions}


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    current: CurrentUser = Depends(get_current_user),
    conn: psycopg.Connection = Depends(get_conn),
):
    ip, ua = client_info(request)
    services.change_password(conn, current.id, body.current_password, body.new_password, ip, ua)
    return MessageResponse(message="Contraseña actualizada. Inicia sesión nuevamente.")


@router.post("/verify-email", response_model=MessageResponse)
def verify_email(body: VerifyEmailRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)):
    ip, ua = client_info(request)
    services.verify_email(conn, body.token, ip, ua)
    return MessageResponse(message="Email verificado")


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(body: ForgotPasswordRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)):
    ip, ua = client_info(request)
    token = services.forgot_password(conn, body.email, ip, ua)
    return MessageResponse(
        message="Si el email existe, recibirás instrucciones para restablecer tu contraseña.",
        debug_token=token if settings.expose_debug_tokens else None,
    )


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(body: ResetPasswordRequest, request: Request, conn: psycopg.Connection = Depends(get_conn)):
    ip, ua = client_info(request)
    services.reset_password(conn, body.token, body.new_password, ip, ua)
    return MessageResponse(message="Contraseña restablecida. Inicia sesión con la nueva contraseña.")
