from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status

from .. import repository as repo
from ..database import get_conn
from ..dependencies import CurrentUser, client_info, require_permissions
from ..schemas import AuditOut, PermissionOut, RoleCreate, RoleOut, SetPermissionsRequest

router = APIRouter(tags=["roles & permissions"])


@router.get("/permissions", response_model=list[PermissionOut])
def list_permissions(
    _: CurrentUser = Depends(require_permissions("users:read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    return repo.list_permissions(conn)


@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    _: CurrentUser = Depends(require_permissions("users:read")),
    conn: psycopg.Connection = Depends(get_conn),
):
    return repo.list_roles(conn)


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(
    body: RoleCreate,
    request: Request,
    current: CurrentUser = Depends(require_permissions("roles:manage")),
    conn: psycopg.Connection = Depends(get_conn),
):
    if repo.get_role_by_name(conn, body.name):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Ya existe un rol con ese nombre")
    role = repo.create_role(conn, body.name, body.description)
    if body.permissions:
        missing = repo.set_role_permissions(conn, role["id"], body.permissions)
        if missing:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Permisos inexistentes: {', '.join(missing)}")
    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "role_created", True, ip, ua, {"role": body.name})
    return repo.get_role(conn, role["id"])


@router.put("/roles/{role_id}/permissions", response_model=RoleOut)
def set_role_permissions(
    role_id: UUID,
    body: SetPermissionsRequest,
    request: Request,
    current: CurrentUser = Depends(require_permissions("roles:manage")),
    conn: psycopg.Connection = Depends(get_conn),
):
    role = repo.get_role(conn, role_id)
    if role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rol no encontrado")
    if role["is_system"] and not current.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Solo un superusuario puede modificar roles del sistema")
    missing = repo.set_role_permissions(conn, role_id, body.permissions)
    if missing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Permisos inexistentes: {', '.join(missing)}")
    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "role_permissions_changed", True, ip, ua,
                      {"role": role["name"], "permissions": sorted(set(body.permissions))})
    return repo.get_role(conn, role_id)


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: UUID,
    request: Request,
    current: CurrentUser = Depends(require_permissions("roles:manage")),
    conn: psycopg.Connection = Depends(get_conn),
):
    role = repo.get_role(conn, role_id)
    if role is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rol no encontrado")
    if role["is_system"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Los roles del sistema no se pueden eliminar")
    repo.delete_role(conn, role_id)
    ip, ua = client_info(request)
    repo.insert_audit(conn, current.id, "role_deleted", True, ip, ua, {"role": role["name"]})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/audit-logs", response_model=list[AuditOut], tags=["audit"])
def list_audit_logs(
    user_id: UUID | None = None,
    event_type: str | None = Query(default=None, max_length=50),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: CurrentUser = Depends(require_permissions("roles:manage")),
    conn: psycopg.Connection = Depends(get_conn),
):
    return repo.list_audit(conn, user_id, event_type, limit, offset)
