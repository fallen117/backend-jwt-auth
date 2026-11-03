import logging
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import database, repository as repo
from .config import settings
from .routers import auth, demo, roles, users

logging.basicConfig(level=logging.INFO, format="%(levelname)s [%(name)s] %(message)s")
logger = logging.getLogger("backend_jwt")


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_pool()
    with database.pool.connection() as conn:
        removed = repo.cleanup_expired(conn)
    logger.info("Pool listo. Limpieza de tokens expirados: %s", removed)
    yield
    database.close_pool()


app = FastAPI(
    title=settings.app_name,
    description="Backend con autenticación y autorización JWT sobre el esquema `jwt_auth` de Supabase.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(psycopg.errors.UniqueViolation)
async def unique_violation_handler(request: Request, exc: psycopg.errors.UniqueViolation):
    # Carrera entre dos registros simultáneos con el mismo email/username
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": "El recurso ya existe"})


@app.get("/health", tags=["health"])
def health():
    try:
        with database.pool.connection() as conn:
            conn.execute("select 1")
    except Exception:
        logger.exception("Health check falló")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="Base de datos no disponible")
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(roles.router)
app.include_router(demo.router)
