from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from .. import repository as repo
from ..config import settings
from ..database import get_conn
from ..dependencies import CurrentUser, client_info, require_permissions
from ..schemas import SetRolesRequest, UserCreate, UserUpdate, UserWithRoles
from ..security import hash_password

router = APIRouter(prefix="/users", tags=["users"])


def _get_or_404(conn: psycopg.Connection, user_id: UUID) -> dict:
    user = repo.get_user_by_id(conn, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user


def _guard_superuser(target: dict, current: CurrentUser) -> None:
    if target["is_superuser"] and not current.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="No puedes modificar a un superusuario")


@router.get("", response_model=list[UserWithRoles])
def list_users(
    search: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: CurrentUser = Depends(require_permissions("users:read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    return repo.list_users(conn, search, limit, offset)


@router.get("/{user_id}", response_model=UserWithRoles)
def get_user(
    user_id: UUID,
    _: CurrentUser = Depends(require_permissions("users:read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    user = repo.get_user_with_roles(conn, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user


@router.post("", response_model=UserWithRoles, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate,
    request: Request,
    current: CurrentUser = Depends(require_permissions("users:write")),
    conn: psycopg.Connection = Depends(get_conn),
):
    if body.roles and not current.has_permission("roles:manage"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Asignar roles requiere el permiso roles:manage")
    if repo.user_exists(conn, body.email, body.username):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="El email o el username ya están registrados")

    user = repo.create_user(
        conn, body.email, body.username, hash_password(body.password), body.full_name, body.is_verified
    )
    if body.roles:
        missing = repo.set_user_roles(conn, user["id"], body.roles, current.id)
        if missing:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Roles inexistentes: {', '.join(missing)}")
    else:
        repo.assign_role_by_name(conn, user["id"], settings.default_role, current.id)

    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "user_created", True, ip, ua, {"target_user_id": str(user["id"])})
    return repo.get_user_with_roles(conn, user["id"])


@router.patch("/{user_id}", response_model=UserWithRoles)
def update_user(
    user_id: UUID,
    body: UserUpdate,
    request: Request,
    current: CurrentUser = Depends(require_permissions("users:write")),
    conn: psycopg.Connection = Depends(get_conn),
):
    target = _get_or_404(conn, user_id)
    _guard_superuser(target, current)
    fields = body.model_dump(exclude_unset=True)

    if user_id == current.id and fields.get("is_active") is False:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No puedes desactivar tu propia cuenta")

    new_email = fields.get("email", target["email"])
    new_username = fields.get("username", target["username"])
    if ("email" in fields or "username" in fields) and repo.user_exists(conn, new_email, new_username, exclude_id=user_id):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="El email o el username ya están registrados")

    repo.update_user(conn, user_id, fields)

    # Desactivar a un usuario corta sus sesiones y le invalida los access tokens vigentes
    if fields.get("is_active") is False:
        repo.revoke_all_user_refresh_tokens(conn, user_id, "user_deactivated")
        repo.bump_token_version(conn, user_id)

    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "user_updated", True, ip, ua,
                      {"target_user_id": str(user_id), "fields": sorted(fields)})
    return repo.get_user_with_roles(conn, user_id)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: UUID,
    request: Request,
    current: CurrentUser = Depends(require_permissions("users:delete")),
    conn: psycopg.Connection = Depends(get_conn),
):
    if user_id == current.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No puedes eliminar tu propia cuenta")
    target = _get_or_404(conn, user_id)
    _guard_superuser(target, current)
    repo.delete_user(conn, user_id)  # cascada: roles, refresh tokens, verificaciones, blacklist
    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "user_deleted", True, ip, ua,
                      {"target_user_id": str(user_id), "username": target["username"]})


@router.put("/{user_id}/roles", response_model=UserWithRoles)
def set_user_roles(
    user_id: UUID,
    body: SetRolesRequest,
    request: Request,
    current: CurrentUser = Depends(require_permissions("roles:manage")),
    conn: psycopg.Connection = Depends(get_conn),
):
    target = _get_or_404(conn, user_id)
    _guard_superuser(target, current)
    missing = repo.set_user_roles(conn, user_id, body.roles, current.id)
    if missing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Roles inexistentes: {', '.join(missing)}")
    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "user_roles_changed", True, ip, ua,
                      {"target_user_id": str(user_id), "roles": sorted(set(body.roles))})
    return repo.get_user_with_roles(conn, user_id)
