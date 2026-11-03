"""Acceso a datos del esquema `jwt_auth`. SQL parametrizado; ninguna entrada del usuario se concatena al SQL."""
import ipaddress
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

Conn = psycopg.Connection
Row = dict[str, Any]

USER_PUBLIC_COLS = (
    "u.id, u.email, u.username, u.full_name, u.is_active, u.is_verified, "
    "u.is_superuser, u.last_login_at, u.created_at"
)
USER_UPDATABLE = {"email", "username", "full_name", "is_active", "is_verified"}


def _ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# =====================================================================
# jwt_users
# =====================================================================
def get_user_by_identifier(conn: Conn, identifier: str) -> Row | None:
    return conn.execute(
        "select * from jwt_auth.jwt_users "
        "where lower(email) = lower(%s) or lower(username) = lower(%s) limit 1",
        (identifier, identifier),
    ).fetchone()


def get_user_by_id(conn: Conn, user_id: UUID) -> Row | None:
    return conn.execute("select * from jwt_auth.jwt_users where id = %s", (user_id,)).fetchone()


def get_user_by_email(conn: Conn, email: str) -> Row | None:
    return conn.execute(
        "select * from jwt_auth.jwt_users where lower(email) = lower(%s)", (email,)
    ).fetchone()


def user_exists(conn: Conn, email: str, username: str, exclude_id: UUID | None = None) -> bool:
    row = conn.execute(
        "select 1 from jwt_auth.jwt_users "
        "where (lower(email) = lower(%s) or lower(username) = lower(%s)) "
        "and (%s::uuid is null or id <> %s::uuid) limit 1",
        (email, username, exclude_id, exclude_id),
    ).fetchone()
    return row is not None


def create_user(
    conn: Conn, email: str, username: str, password_hash: str, full_name: str | None, is_verified: bool
) -> Row:
    return conn.execute(
        "insert into jwt_auth.jwt_users (email, username, password_hash, full_name, is_verified) "
        "values (%s, %s, %s, %s, %s) returning *",
        (email, username, password_hash, full_name, is_verified),
    ).fetchone()


def list_users(conn: Conn, search: str | None, limit: int, offset: int) -> list[Row]:
    pattern = f"%{search}%" if search else None
    return conn.execute(
        f"""
        select {USER_PUBLIC_COLS},
               array(select r.name from jwt_auth.jwt_user_roles ur
                     join jwt_auth.jwt_roles r on r.id = ur.role_id
                     where ur.user_id = u.id order by r.name) as roles
        from jwt_auth.jwt_users u
        where (%(p)s::text is null or u.email ilike %(p)s or u.username ilike %(p)s or u.full_name ilike %(p)s)
        order by u.created_at desc
        limit %(limit)s offset %(offset)s
        """,
        {"p": pattern, "limit": limit, "offset": offset},
    ).fetchall()


def get_user_with_roles(conn: Conn, user_id: UUID) -> Row | None:
    return conn.execute(
        f"""
        select {USER_PUBLIC_COLS},
               array(select r.name from jwt_auth.jwt_user_roles ur
                     join jwt_auth.jwt_roles r on r.id = ur.role_id
                     where ur.user_id = u.id order by r.name) as roles
        from jwt_auth.jwt_users u where u.id = %s
        """,
        (user_id,),
    ).fetchone()


def update_user(conn: Conn, user_id: UUID, fields: dict[str, Any]) -> Row | None:
    fields = {k: v for k, v in fields.items() if k in USER_UPDATABLE}
    if not fields:
        return get_user_by_id(conn, user_id)
    assignments = sql.SQL(", ").join(
        sql.SQL("{} = {}").format(sql.Identifier(k), sql.Placeholder(k)) for k in fields
    )
    query = sql.SQL("update jwt_auth.jwt_users set {} where id = {} returning *").format(
        assignments, sql.Placeholder("_id")
    )
    return conn.execute(query, {**fields, "_id": user_id}).fetchone()


def delete_user(conn: Conn, user_id: UUID) -> bool:
    return conn.execute("delete from jwt_auth.jwt_users where id = %s", (user_id,)).rowcount > 0


def register_failed_login(conn: Conn, user_id: UUID, max_attempts: int, lock_minutes: int) -> Row:
    return conn.execute(
        """
        update jwt_auth.jwt_users set
          failed_login_attempts = failed_login_attempts + 1,
          locked_until = case when failed_login_attempts + 1 >= %(max)s
                              then now() + make_interval(mins => %(mins)s)
                              else locked_until end
        where id = %(id)s
        returning failed_login_attempts, locked_until
        """,
        {"max": max_attempts, "mins": lock_minutes, "id": user_id},
    ).fetchone()


def mark_login_success(conn: Conn, user_id: UUID) -> None:
    conn.execute(
        "update jwt_auth.jwt_users set failed_login_attempts = 0, locked_until = null, "
        "last_login_at = now() where id = %s",
        (user_id,),
    )


def set_password(conn: Conn, user_id: UUID, password_hash: str) -> None:
    """Cambia la contraseña e incrementa token_version (invalida todos los access tokens vigentes)."""
    conn.execute(
        "update jwt_auth.jwt_users set password_hash = %s, password_changed_at = now(), "
        "token_version = token_version + 1, failed_login_attempts = 0, locked_until = null "
        "where id = %s",
        (password_hash, user_id),
    )


def bump_token_version(conn: Conn, user_id: UUID) -> None:
    conn.execute(
        "update jwt_auth.jwt_users set token_version = token_version + 1 where id = %s", (user_id,)
    )


def mark_verified(conn: Conn, user_id: UUID) -> None:
    conn.execute("update jwt_auth.jwt_users set is_verified = true where id = %s", (user_id,))


# =====================================================================
# jwt_roles / jwt_permissions / jwt_user_roles / jwt_role_permissions
# =====================================================================
def get_user_roles(conn: Conn, user_id: UUID) -> list[str]:
    rows = conn.execute(
        "select r.name from jwt_auth.jwt_user_roles ur "
        "join jwt_auth.jwt_roles r on r.id = ur.role_id where ur.user_id = %s order by r.name",
        (user_id,),
    ).fetchall()
    return [r["name"] for r in rows]


def get_user_permissions(conn: Conn, user_id: UUID, is_superuser: bool) -> list[str]:
    if is_superuser:
        rows = conn.execute("select code as permission_code from jwt_auth.jwt_permissions order by code").fetchall()
    else:
        rows = conn.execute(
            "select permission_code from jwt_auth.jwt_user_effective_permissions "
            "where user_id = %s order by permission_code",
            (user_id,),
        ).fetchall()
    return [r["permission_code"] for r in rows]


def set_user_roles(conn: Conn, user_id: UUID, role_names: list[str], assigned_by: UUID | None) -> list[str]:
    """Reemplaza los roles del usuario. Devuelve la lista de roles inexistentes (vacía si todo OK)."""
    names = sorted(set(role_names))
    rows = conn.execute(
        "select id, name from jwt_auth.jwt_roles where name = any(%s)", (names,)
    ).fetchall()
    found = {r["name"]: r["id"] for r in rows}
    missing = sorted(set(names) - set(found))
    if missing:
        return missing
    conn.execute("delete from jwt_auth.jwt_user_roles where user_id = %s", (user_id,))
    for role_id in found.values():
        conn.execute(
            "insert into jwt_auth.jwt_user_roles (user_id, role_id, assigned_by) values (%s, %s, %s)",
            (user_id, role_id, assigned_by),
        )
    return []


def assign_role_by_name(conn: Conn, user_id: UUID, role_name: str, assigned_by: UUID | None = None) -> bool:
    return (
        conn.execute(
            "insert into jwt_auth.jwt_user_roles (user_id, role_id, assigned_by) "
            "select %s, id, %s from jwt_auth.jwt_roles where name = %s on conflict do nothing",
            (user_id, assigned_by, role_name),
        ).rowcount
        > 0
    )


def list_permissions(conn: Conn) -> list[Row]:
    return conn.execute(
        "select id, code, resource, action, description from jwt_auth.jwt_permissions order by code"
    ).fetchall()


_ROLE_SELECT = """
    select r.id, r.name, r.description, r.is_system,
           array(select p.code from jwt_auth.jwt_role_permissions rp
                 join jwt_auth.jwt_permissions p on p.id = rp.permission_id
                 where rp.role_id = r.id order by p.code) as permissions
    from jwt_auth.jwt_roles r
"""


def list_roles(conn: Conn) -> list[Row]:
    return conn.execute(_ROLE_SELECT + " order by r.name").fetchall()


def get_role(conn: Conn, role_id: UUID) -> Row | None:
    return conn.execute(_ROLE_SELECT + " where r.id = %s", (role_id,)).fetchone()


def get_role_by_name(conn: Conn, name: str) -> Row | None:
    return conn.execute(_ROLE_SELECT + " where r.name = %s", (name,)).fetchone()


def create_role(conn: Conn, name: str, description: str | None) -> Row:
    return conn.execute(
        "insert into jwt_auth.jwt_roles (name, description) values (%s, %s) returning id", (name, description)
    ).fetchone()


def delete_role(conn: Conn, role_id: UUID) -> bool:
    return conn.execute(
        "delete from jwt_auth.jwt_roles where id = %s and is_system = false", (role_id,)
    ).rowcount > 0


def set_role_permissions(conn: Conn, role_id: UUID, codes: list[str]) -> list[str]:
    """Reemplaza los permisos del rol. Devuelve los códigos inexistentes (vacía si todo OK)."""
    codes = sorted(set(codes))
    rows = conn.execute(
        "select id, code from jwt_auth.jwt_permissions where code = any(%s)", (codes,)
    ).fetchall()
    found = {r["code"]: r["id"] for r in rows}
    missing = sorted(set(codes) - set(found))
    if missing:
        return missing
    conn.execute("delete from jwt_auth.jwt_role_permissions where role_id = %s", (role_id,))
    for perm_id in found.values():
        conn.execute(
            "insert into jwt_auth.jwt_role_permissions (role_id, permission_id) values (%s, %s)",
            (role_id, perm_id),
        )
    return []


# =====================================================================
# jwt_refresh_tokens
# =====================================================================
def insert_refresh_token(
    conn: Conn,
    user_id: UUID,
    jti: UUID,
    token_hash: str,
    family_id: UUID,
    expires_at: datetime,
    ip: str | None,
    user_agent: str | None,
) -> Row:
    return conn.execute(
        "insert into jwt_auth.jwt_refresh_tokens "
        "(user_id, jti, token_hash, family_id, expires_at, ip_address, user_agent) "
        "values (%s, %s, %s, %s, %s, %s::inet, %s) returning id",
        (user_id, jti, token_hash, family_id, expires_at, _ip(ip), (user_agent or "")[:300] or None),
    ).fetchone()


def get_refresh_token_for_update(conn: Conn, token_hash: str) -> Row | None:
    return conn.execute(
        "select * from jwt_auth.jwt_refresh_tokens where token_hash = %s for update", (token_hash,)
    ).fetchone()


def revoke_refresh_token(conn: Conn, token_id: UUID, reason: str, replaced_by: UUID | None = None) -> None:
    conn.execute(
        "update jwt_auth.jwt_refresh_tokens set revoked_at = now(), revoked_reason = %s, replaced_by = %s "
        "where id = %s and revoked_at is null",
        (reason, replaced_by, token_id),
    )


def revoke_family(conn: Conn, family_id: UUID, reason: str) -> None:
    conn.execute(
        "update jwt_auth.jwt_refresh_tokens set revoked_at = now(), revoked_reason = %s "
        "where family_id = %s and revoked_at is null",
        (reason, family_id),
    )


def revoke_all_user_refresh_tokens(conn: Conn, user_id: UUID, reason: str) -> None:
    conn.execute(
        "update jwt_auth.jwt_refresh_tokens set revoked_at = now(), revoked_reason = %s "
        "where user_id = %s and revoked_at is null",
        (reason, user_id),
    )


# =====================================================================
# jwt_token_blacklist
# =====================================================================
def blacklist_token(
    conn: Conn, jti: UUID, user_id: UUID | None, token_type: str, reason: str, expires_at: datetime
) -> None:
    conn.execute(
        "insert into jwt_auth.jwt_token_blacklist (jti, user_id, token_type, reason, expires_at) "
        "values (%s, %s, %s, %s, %s) on conflict (jti) do nothing",
        (jti, user_id, token_type, reason, expires_at),
    )


def is_blacklisted(conn: Conn, jti: UUID) -> bool:
    return conn.execute("select 1 from jwt_auth.jwt_token_blacklist where jti = %s", (jti,)).fetchone() is not None


# =====================================================================
# jwt_verification_tokens
# =====================================================================
def create_verification_token(
    conn: Conn, user_id: UUID, purpose: str, token_hash: str, expires_at: datetime
) -> None:
    # Invalida los tokens anteriores sin usar del mismo propósito
    conn.execute(
        "update jwt_auth.jwt_verification_tokens set used_at = now() "
        "where user_id = %s and purpose = %s and used_at is null",
        (user_id, purpose),
    )
    conn.execute(
        "insert into jwt_auth.jwt_verification_tokens (user_id, purpose, token_hash, expires_at) "
        "values (%s, %s, %s, %s)",
        (user_id, purpose, token_hash, expires_at),
    )


def get_verification_token_for_update(conn: Conn, token_hash: str, purpose: str) -> Row | None:
    return conn.execute(
        "select * from jwt_auth.jwt_verification_tokens where token_hash = %s and purpose = %s for update",
        (token_hash, purpose),
    ).fetchone()


def mark_verification_token_used(conn: Conn, token_id: UUID) -> None:
    conn.execute("update jwt_auth.jwt_verification_tokens set used_at = now() where id = %s", (token_id,))


# =====================================================================
# jwt_audit_log
# =====================================================================
def insert_audit(
    conn: Conn,
    user_id: UUID | None,
    event_type: str,
    success: bool,
    ip: str | None,
    user_agent: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    conn.execute(
        "insert into jwt_auth.jwt_audit_log (user_id, event_type, success, ip_address, user_agent, details) "
        "values (%s, %s, %s, %s::inet, %s, %s)",
        (user_id, event_type, success, _ip(ip), (user_agent or "")[:300] or None, Jsonb(details or {})),
    )


def list_audit(
    conn: Conn, user_id: UUID | None, event_type: str | None, limit: int, offset: int
) -> list[Row]:
    return conn.execute(
        """
        select id, user_id, event_type, success, host(ip_address) as ip_address, user_agent, details, created_at
        from jwt_auth.jwt_audit_log
        where (%(uid)s::uuid is null or user_id = %(uid)s::uuid)
          and (%(ev)s::text is null or event_type = %(ev)s::text)
        order by created_at desc, id desc
        limit %(limit)s offset %(offset)s
        """,
        {"uid": user_id, "ev": event_type, "limit": limit, "offset": offset},
    ).fetchall()


# =====================================================================
# Mantenimiento
# =====================================================================
def cleanup_expired(conn: Conn) -> dict[str, int]:
    """Elimina tokens expirados (se ejecuta al iniciar la app)."""
    refresh = conn.execute(
        "delete from jwt_auth.jwt_refresh_tokens where expires_at < now() - interval '1 day'"
    ).rowcount
    blacklist = conn.execute("delete from jwt_auth.jwt_token_blacklist where expires_at < now()").rowcount
    verification = conn.execute(
        "delete from jwt_auth.jwt_verification_tokens where expires_at < now() - interval '1 day'"
    ).rowcount
    return {"refresh_tokens": refresh, "blacklist": blacklist, "verification_tokens": verification}
