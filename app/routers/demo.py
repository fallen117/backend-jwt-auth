"""Endpoints de demostración para probar autorización por permisos y por roles."""
from fastapi import APIRouter, Depends

from ..dependencies import CurrentUser, get_current_user, require_permissions, require_roles

router = APIRouter(prefix="/demo", tags=["demo (autorización)"])


@router.get("/public")
def public():
    """Sin autenticación."""
    return {"message": "Endpoint público"}


@router.get("/protected")
def protected(current: CurrentUser = Depends(get_current_user)):
    """Cualquier usuario autenticado."""
    return {"message": f"Hola {current.username}", "roles": current.roles}


@router.get("/posts")
def read_posts(current: CurrentUser = Depends(require_permissions("posts:read"))):
    """Requiere el permiso posts:read (admin, editor, viewer)."""
    return {"posts": [{"id": 1, "title": "Primer post"}, {"id": 2, "title": "Segundo post"}]}


@router.post("/posts")
def create_post(current: CurrentUser = Depends(require_permissions("posts:write"))):
    """Requiere el permiso posts:write (admin, editor)."""
    return {"message": "Post creado", "author": current.username}


@router.delete("/posts/{post_id}")
def delete_post(post_id: int, current: CurrentUser = Depends(require_permissions("posts:delete"))):
    """Requiere el permiso posts:delete (solo admin)."""
    return {"message": f"Post {post_id} eliminado", "by": current.username}


@router.get("/admin-only")
def admin_only(current: CurrentUser = Depends(require_roles("admin"))):
    """Autorización por ROL en lugar de permiso."""
    return {"message": "Zona solo para admins", "user": current.username}
