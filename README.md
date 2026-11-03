# Backend JWT (FastAPI + Supabase Postgres)

Backend con **autenticación y autorización JWT** sobre el esquema `jwt_auth` (tablas `jwt_*`) de Supabase.

## Estructura

```
backend-jwt/
├── requirements.txt
├── .env.example          # copiar a .env
├── README.md
└── app/
    ├── main.py           # FastAPI, CORS, lifespan (pool + limpieza de tokens expirados)
    ├── config.py         # Settings desde .env
    ├── database.py       # Pool psycopg 3 (síncrono)
    ├── security.py       # bcrypt, creación/validación de JWT, hash SHA-256 de tokens
    ├── schemas.py        # Modelos Pydantic
    ├── repository.py     # SQL sobre las tablas jwt_*
    ├── services.py       # Lógica: login, refresh rotativo, logout, reset de contraseña...
    ├── dependencies.py   # get_current_user, require_permissions, require_roles
    └── routers/
        ├── auth.py       # /auth/*
        ├── users.py      # /users/*
        ├── roles.py      # /roles, /permissions, /audit-logs
        └── demo.py       # /demo/* para probar autorización
```

## Instalación (Windows / PowerShell)

```powershell
cd "C:\Users\Aprendiz\Desktop\api lessons\backend-jwt"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edita `.env`:

1. **`DATABASE_URL`**: en Supabase ve a *Connect* y copia la cadena. Si tu red no tiene IPv6, usa **Session pooler**
   (la conexión directa `db.<ref>.supabase.co` es solo IPv6). Reemplaza `TU_PASSWORD`; si tiene caracteres
   especiales, codifícalos en formato URL.
2. **`JWT_SECRET_KEY`**: genera una con
   `python -c "import secrets; print(secrets.token_urlsafe(64))"`

Ejecutar:

```powershell
uvicorn app.main:app --reload
```

- Swagger: http://127.0.0.1:8000/docs (botón **Authorize**: usa email o username + contraseña)
- Health: http://127.0.0.1:8000/health

## Usuarios de ejemplo (ya están en la BD)

| Usuario | Contraseña | Rol | Permisos |
|---|---|---|---|
| `admin@example.com` | `Admin123!` | admin (superusuario) | todos |
| `editor@example.com` | `Editor123!` | editor | `posts:read`, `posts:write`, `users:read` |
| `viewer@example.com` | `Viewer123!` | viewer | `posts:read` |

## Cómo se usan las tablas

| Tabla | Uso en el backend |
|---|---|
| `jwt_users` | Credenciales (bcrypt), bloqueo (`failed_login_attempts`, `locked_until`), `token_version` |
| `jwt_roles`, `jwt_permissions`, `jwt_user_roles`, `jwt_role_permissions` | RBAC. Se resuelven con la vista `jwt_user_effective_permissions` |
| `jwt_refresh_tokens` | Refresh tokens opacos (solo su SHA-256), rotación por `family_id`, detección de reuso |
| `jwt_token_blacklist` | Access tokens revocados por `jti` (logout) |
| `jwt_verification_tokens` | Verificación de email y reset de contraseña (un solo uso) |
| `jwt_audit_log` | Registro de login, logout, refresh, cambios de roles, etc. |

## Flujo de seguridad

- **Login**: busca por email o username, compara bcrypt, y tras `MAX_FAILED_LOGIN_ATTEMPTS` fallos bloquea la
  cuenta `LOCKOUT_MINUTES` (HTTP 423). Con usuario inexistente igual ejecuta un bcrypt ficticio para no filtrar por tiempos.
- **Access token** (JWT HS256, 15 min): claims `sub`, `jti`, `iss`, `iat`, `exp`, `type`, `ver`, `roles`, `perms`.
- **Refresh token**: cadena aleatoria; en BD solo se guarda su hash. Cada `/auth/refresh` lo **rota**. Si se
  presenta uno ya rotado, se revoca toda la sesión (`family_id`) por posible robo.
- **Validación por request** (`get_current_user`): firma/expiración → blacklist (`jti`) → usuario activo →
  `ver == token_version`. Roles y permisos se leen de la BD, por lo que los cambios aplican de inmediato.
- **Invalidación masiva**: cambiar/resetear contraseña, `logout-all` o desactivar un usuario incrementa `token_version`
  y revoca sus refresh tokens.
- **Autorización**: `require_permissions("posts:write")` (todos los indicados) o `require_roles("admin")` (al menos uno).
  El superusuario siempre pasa.

## Endpoints

| Método | Ruta | Acceso |
|---|---|---|
| POST | `/auth/register` | público |
| POST | `/auth/login` · `/auth/token` | público |
| POST | `/auth/refresh` | público (con refresh token) |
| POST | `/auth/verify-email` · `/auth/forgot-password` · `/auth/reset-password` | público |
| GET | `/auth/me` | autenticado |
| POST | `/auth/logout` · `/auth/logout-all` · `/auth/change-password` | autenticado |
| GET | `/users`, `/users/{id}` | `users:read` |
| POST/PATCH | `/users`, `/users/{id}` | `users:write` |
| DELETE | `/users/{id}` | `users:delete` |
| PUT | `/users/{id}/roles` | `roles:manage` |
| GET | `/roles`, `/permissions` | `users:read` |
| POST/DELETE/PUT | `/roles`, `/roles/{id}`, `/roles/{id}/permissions` | `roles:manage` |
| GET | `/audit-logs` | `roles:manage` |
| GET/POST/DELETE | `/demo/posts…`, `/demo/admin-only` | `posts:*` / rol `admin` |

## Pruebas rápidas (PowerShell)

```powershell
$base = "http://127.0.0.1:8000"

# Login
$login = Invoke-RestMethod -Method Post -Uri "$base/auth/login" -ContentType "application/json" `
  -Body '{"identifier":"editor@example.com","password":"Editor123!"}'
$h = @{ Authorization = "Bearer $($login.access_token)" }

Invoke-RestMethod "$base/auth/me" -Headers $h              # perfil, roles y permisos
Invoke-RestMethod "$base/demo/posts" -Headers $h           # OK (posts:read)
Invoke-RestMethod -Method Post "$base/demo/posts" -Headers $h   # OK (posts:write)
Invoke-RestMethod -Method Delete "$base/demo/posts/1" -Headers $h  # 403 (editor no tiene posts:delete)

# Refresh (rota el refresh token)
$new = Invoke-RestMethod -Method Post -Uri "$base/auth/refresh" -ContentType "application/json" `
  -Body (@{ refresh_token = $login.refresh_token } | ConvertTo-Json)

# Logout (revoca el access token actual)
Invoke-RestMethod -Method Post "$base/auth/logout" -Headers $h
```

## Notas para producción

- Define `EXPOSE_DEBUG_TOKENS=false` e implementa el envío real de emails en `services._send_email_stub`.
- Añade *rate limiting* (p. ej. `slowapi` o en el proxy) en `/auth/login`, `/auth/refresh` y `/auth/forgot-password`.
- Usa HTTPS y restringe `CORS_ORIGINS` a tus dominios reales.
- Detrás de un proxy inverso ejecuta uvicorn con `--proxy-headers` para registrar la IP real.
- Programa la limpieza de `jwt_refresh_tokens`, `jwt_token_blacklist` y `jwt_verification_tokens` expirados
  (`repository.cleanup_expired` ya se ejecuta al iniciar la app; también puedes usar `pg_cron`).
- Cambia las contraseñas de los usuarios de ejemplo.
