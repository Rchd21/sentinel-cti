"""Schéma de la base. Compatible SQLite (local) et PostgreSQL (docker compose)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from sentinel.config import settings


class Base(DeclarativeBase):
    pass


class AdvisoryRow(Base):
    __tablename__ = "advisories"
    __table_args__ = (UniqueConstraint("source", "ref_id", name="uq_source_ref"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    ref_id: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    cves: Mapped[list[str]] = mapped_column(JSON, default=list)
    content_hash: Mapped[str] = mapped_column(String(64))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def get_engine(url: str | None = None) -> Engine:
    url = url or settings.database_url
    if url.startswith("sqlite:///") and not url.endswith(":memory:"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, future=True)
    Base.metadata.create_all(engine)  # migrations Alembic plus tard (Phase 7)
    return engine
