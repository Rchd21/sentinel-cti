"""Stockage des CVE et de leur gravité (table cves)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from sentinel.db.schema import AdvisoryRow, CveRow
from sentinel.models import CveRecord

# Une CVE trop récente n'a souvent pas encore de score : on la relit après ce délai.
RECHECK_UNSCORED_AFTER = timedelta(days=7)

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")


def as_utc(value: datetime) -> datetime:
    """SQLite rend des dates sans fuseau : on les considère en UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class CveRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def pending(self, limit: int = 100, now: datetime | None = None) -> list[str]:
        """CVE citées dans les avis, à (re)lire dans la NVD. Avis les plus récents d'abord."""
        if limit <= 0:
            return []
        now = now or datetime.now(UTC)
        with Session(self.engine) as session:
            known = {row.cve_id: row for row in session.scalars(select(CveRow))}
            advisories = session.scalars(
                select(AdvisoryRow).order_by(AdvisoryRow.published_at.desc().nullslast())
            )
            todo: list[str] = []
            seen: set[str] = set()
            for advisory in advisories:
                for cve_id in advisory.cves or []:
                    if cve_id in seen:
                        continue
                    seen.add(cve_id)
                    row = known.get(cve_id)
                    if row is None or (
                        row.cvss_score is None
                        and now - as_utc(row.fetched_at) > RECHECK_UNSCORED_AFTER
                    ):
                        todo.append(cve_id)
                        if len(todo) >= limit:
                            return todo
            return todo

    def save(self, record: CveRecord) -> None:
        """Crée ou remplace la fiche d'une CVE."""
        with Session(self.engine) as session, session.begin():
            row = session.get(CveRow, record.cve_id) or CveRow(cve_id=record.cve_id)
            row.description = record.description
            row.cvss_version = record.cvss_version
            row.cvss_score = record.cvss_score
            row.severity = record.severity
            row.vector = record.vector
            row.cwes = record.cwes
            row.nvd_status = record.nvd_status
            row.published_at = record.published_at
            row.cisa_kev_added = record.cisa_kev_added
            row.fetched_at = record.fetched_at
            session.add(row)

    def get(self, cve_id: str) -> CveRow | None:
        with Session(self.engine) as session:
            return session.get(CveRow, cve_id)

    def for_ids(self, cve_ids: list[str]) -> list[CveRow]:
        """Fiches connues pour une liste de CVE, de la plus grave à la moins grave."""
        if not cve_ids:
            return []
        with Session(self.engine) as session:
            rows = list(session.scalars(select(CveRow).where(CveRow.cve_id.in_(cve_ids))))
        return sorted(rows, key=lambda r: r.cvss_score or 0, reverse=True)


def severity_counts(rows: list[CveRow]) -> dict[str, int]:
    """{"CRITICAL": 3, "HIGH": 12, ...} dans l'ordre de gravité, sans les zéros."""
    counts = {level: 0 for level in SEVERITY_ORDER}
    for row in rows:
        if row.severity in counts:
            counts[row.severity] += 1
    return {level: n for level, n in counts.items() if n}
