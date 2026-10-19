"""Écriture idempotente des avis : relancer une collecte ne crée jamais de doublon."""

from __future__ import annotations

from dataclasses import dataclass

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
                    row.title, row.summary, row.cves = adv.title, adv.summary, adv.cves
                    row.content_hash = adv.content_hash
                    row.last_seen_at = adv.collected_at
                    stats.updated += 1
                else:
                    row.last_seen_at = adv.collected_at
                    stats.unchanged += 1
        return stats

    def latest(self, limit: int = 10) -> list[AdvisoryRow]:
        with Session(self.engine) as session:
            stmt = (
                select(AdvisoryRow)
                .order_by(AdvisoryRow.published_at.desc().nullslast())
                .limit(limit)
            )
            return list(session.scalars(stmt))
