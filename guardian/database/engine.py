"""SQLAlchemy engine and session factory."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from guardian.core.config import get_settings
from guardian.core.models import Base

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def get_engine(database_url: str | None = None) -> Engine:
    """Return (and lazily create) the global SQLAlchemy engine."""
    global _engine, _SessionFactory
    if _engine is None or database_url is not None:
        url = database_url or get_settings().database_url
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, echo=get_settings().debug, connect_args=connect_args, future=True)
        _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)
    return _engine


def init_db(database_url: str | None = None) -> Engine:
    """Create all tables."""
    engine = get_engine(database_url)
    Base.metadata.create_all(engine)
    return engine


def get_session_factory() -> sessionmaker[Session]:
    if _SessionFactory is None:
        get_engine()
    assert _SessionFactory is not None
    return _SessionFactory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Provide a transactional scope around a series of operations."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Session:
    """Return a new session (caller manages lifecycle)."""
    return get_session_factory()()
