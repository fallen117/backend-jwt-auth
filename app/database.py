"""Pool de conexiones a Postgres (psycopg 3, modo síncrono).

Se usa modo síncrono a propósito: los endpoints `def` de FastAPI corren en un threadpool
y así se evita el problema de psycopg async con el event loop por defecto de Windows.
"""
from collections.abc import Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .config import settings

pool: ConnectionPool | None = None


def init_pool() -> None:
    global pool
    pool = ConnectionPool(
        conninfo=settings.database_url,
        min_size=settings.db_pool_min_size,
        max_size=settings.db_pool_max_size,
        # prepare_threshold=None -> compatible con el pooler de Supabase en modo transacción (puerto 6543)
        kwargs={"row_factory": dict_row, "prepare_threshold": None},
        open=False,
    )
    pool.open(wait=True, timeout=30)


def close_pool() -> None:
    global pool
    if pool is not None:
        pool.close()
        pool = None


def get_conn() -> Iterator[psycopg.Connection]:
    """Dependencia de FastAPI: una conexión por request.

    Hace COMMIT si el endpoint termina bien y ROLLBACK si lanza una excepción.
    Cuando hay que persistir algo y aun así devolver un error (p. ej. un login fallido),
    se llama a `conn.commit()` explícitamente antes de lanzar la HTTPException.
    """
    assert pool is not None, "El pool de base de datos no está inicializado"
    with pool.connection() as conn:
        yield conn
