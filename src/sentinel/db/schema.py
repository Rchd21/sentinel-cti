"""Schéma de la base. Compatible SQLite (local) et PostgreSQL (docker compose)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    inspect,
    text,
)
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
    # Détail de l'avis (étape d'enrichissement)
    affected_systems: Mapped[list[dict]] = mapped_column(JSON, default=list)
    risks: Mapped[list[str]] = mapped_column(JSON, default=list)
    details_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CveRow(Base):
    """Une faille (CVE) et sa gravité selon la NVD. Une ligne par CVE, partagée par les avis."""

    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str] = mapped_column(Text, default="")
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_score: Mapped[float | None] = mapped_column(Float, index=True)
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    vector: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str]] = mapped_column(JSON, default=list)
    nvd_status: Mapped[str] = mapped_column(String(32), default="")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cisa_kev_added: Mapped[str | None] = mapped_column(String(10))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def get_engine(url: str | None = None) -> Engine:
    url = url or settings.database_url
    if url.startswith("sqlite:///") and not url.endswith(":memory:"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, future=True)
    Base.metadata.create_all(engine)  # crée les tables qui n'existent pas encore
    add_missing_columns(engine)  # migrations Alembic plus tard (Phase 7)
    return engine


def add_missing_columns(engine: Engine) -> None:
    """Ajoute aux tables existantes les colonnes déclarées dans le code mais absentes en base."""
    inspector = inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {col["name"] for col in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing:
                continue
            col_type = column.type.compile(dialect=engine.dialect)
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table.name} ADD COLUMN {column.name} {col_type}"))
