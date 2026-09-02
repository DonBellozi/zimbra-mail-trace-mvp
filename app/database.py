from __future__ import annotations

from collections.abc import Iterator
from threading import RLock

from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .models import Base


class DatabaseManager:
    def __init__(self) -> None:
        self._engine: Engine | None = None
        self._url: str | None = None
        self._lock = RLock()

    def connect(self, url: str, create: bool = True) -> Engine:
        with self._lock:
            if self._engine is None or self._url != url:
                candidate = create_engine(url, pool_pre_ping=True)
                with candidate.connect() as conn:
                    conn.execute(text("SELECT 1"))
                if create:
                    Base.metadata.create_all(candidate)
                old, self._engine, self._url = self._engine, candidate, url
                if old:
                    old.dispose()
            return self._engine

    def session(self, url: str) -> Iterator[Session]:
        with Session(self.connect(url)) as session:
            yield session

    @staticmethod
    def test(url: str) -> dict:
        engine = create_engine(url, pool_pre_ping=True)
        try:
            with engine.connect() as conn:
                version = conn.execute(text("SHOW server_version")).scalar_one()
            return {"ok": True, "version": version}
        finally:
            engine.dispose()

    @staticmethod
    def migrate(source_url: str, target_url: str, allow_nonempty: bool = False) -> dict:
        source = create_engine(source_url, pool_pre_ping=True)
        target = create_engine(target_url, pool_pre_ping=True)
        try:
            Base.metadata.create_all(target)
            tables = list(Base.metadata.sorted_tables)
            with source.connect() as src, target.begin() as dst:
                existing = sum(dst.execute(text(f'SELECT COUNT(*) FROM "{t.name}"')).scalar_one() for t in tables)
                if existing and not allow_nonempty:
                    raise ValueError("Целевая база не пуста")
                copied: dict[str, int] = {}
                for table in tables:
                    rows = src.execute(select(table)).mappings().all()
                    if rows:
                        dst.execute(table.insert(), [dict(row) for row in rows])
                    copied[table.name] = len(rows)
            with target.connect() as check:
                verified = {t.name: check.execute(text(f'SELECT COUNT(*) FROM "{t.name}"')).scalar_one() for t in tables}
            return {"ok": True, "copied": copied, "verified": verified}
        finally:
            source.dispose()
            target.dispose()


db = DatabaseManager()
