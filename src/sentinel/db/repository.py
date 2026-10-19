"""Écriture idempotente des avis : relancer une collecte ne crée jamais de doublon."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from sentinel.db.schema import AdvisoryRow
from sentinel.models import Advisory


@dataclass
class UpsertStats:
    new: int = 0
    updated: int = 0
    unchanged: int = 0

    def __str__(self) -> str:
        return f"{self.new} nouveaux, {self.updated} mis à jour, {self.unchanged} inchangés"


class AdvisoryRepository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def upsert_many(self, advisories: list[Advisory]) -> UpsertStats:
        # Un même avis peut apparaître dans plusieurs flux (ex. "avis" et "scada").
        unique = {(a.source, a.ref_id): a for a in advisories}
        stats = UpsertStats()

        with Session(self.engine) as session, session.begin():
            for (source, ref_id), adv in unique.items():
                row = session.scalar(
                    select(AdvisoryRow).where(
                        AdvisoryRow.source == source, AdvisoryRow.ref_id == ref_id
                    )
                )
                if row is None:
                    session.add(
                        AdvisoryRow(
                            source=source,
                            ref_id=ref_id,
                            kind=adv.kind,
                            title=adv.title,
                            url=adv.url,
                            published_at=adv.published_at,
                            summary=adv.summary,
                            cves=adv.cves,
                            content_hash=adv.content_hash,
                            first_seen_at=adv.collected_at,
                            last_seen_at=adv.collected_at,
                        )
                    )
                    stats.new += 1
                elif row.content_hash != adv.content_hash:
                    row.title, row.summary = adv.title, adv.summary
                    # On fusionne : ne jamais perdre les CVE trouvées lors de l'enrichissement.
                    row.cves = sorted(set(row.cves or []) | set(adv.cves))
                    row.content_hash = adv.content_hash
                    row.last_seen_at = adv.collected_at
                    row.details_fetched_at = None  # l'avis a changé : on relira son détail
                    stats.updated += 1
                else:
                    row.last_seen_at = adv.collected_at
                    stats.unchanged += 1
        return stats

    def pending_details(self, source: str, limit: int = 50) -> list[tuple[str, str]]:
        """Avis dont le détail n'a pas encore été récupéré : [(ref_id, url), ...]."""
        with Session(self.engine) as session:
            stmt = (
                select(AdvisoryRow.ref_id, AdvisoryRow.url)
                .where(AdvisoryRow.source == source, AdvisoryRow.details_fetched_at.is_(None))
                .order_by(AdvisoryRow.published_at.desc().nullslast())
                .limit(limit)
            )
            return [(ref_id, url) for ref_id, url in session.execute(stmt)]

    def save_details(
        self,
        source: str,
        ref_id: str,
        *,
        found: bool,
        cves: list[str] | None = None,
        affected_systems: list[dict] | None = None,
        risks: list[str] | None = None,
    ) -> None:
        """Enregistre le détail d'un avis et note qu'il a été traité."""
        with Session(self.engine) as session, session.begin():
            row = session.scalar(
                select(AdvisoryRow).where(
                    AdvisoryRow.source == source, AdvisoryRow.ref_id == ref_id
                )
            )
            if row is None:
                return
            if found:
                row.cves = sorted(set(row.cves or []) | set(cves or []))
                row.affected_systems = affected_systems or []
                row.risks = risks or []
            row.details_fetched_at = datetime.now(UTC)

    def get(self, source: str, ref_id: str) -> AdvisoryRow | None:
        with Session(self.engine) as session:
            return session.scalar(
                select(AdvisoryRow).where(
                    AdvisoryRow.source == source, AdvisoryRow.ref_id == ref_id
                )
            )

    def latest(self, limit: int = 10) -> list[AdvisoryRow]:
        with Session(self.engine) as session:
            stmt = (
                select(AdvisoryRow)
                .order_by(AdvisoryRow.published_at.desc().nullslast())
                .limit(limit)
            )
            return list(session.scalars(stmt))
