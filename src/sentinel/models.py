"""Objets métier communs à toutes les sources."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class Advisory:
    """Un avis, une alerte ou un rapport publié par une source, normalisé."""

    source: str  # ex. "certfr"
    ref_id: str  # identifiant stable chez la source, ex. "CERTFR-2026-AVI-1342"
    kind: str  # avis | alerte | cti | ioc | scada | dur | actualite
    title: str
    url: str
    published_at: datetime | None
    summary: str = ""
    cves: list[str] = field(default_factory=list)
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def content_hash(self) -> str:
        """Empreinte du contenu : permet de détecter qu'un avis a été mis à jour."""
        payload = "|".join([self.title, self.summary, ",".join(sorted(self.cves))])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
