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


@dataclass
class CveRecord:
    """Une faille (CVE) et sa gravité, normalisée depuis la NVD."""

    cve_id: str  # ex. "CVE-2026-24101"
    description: str = ""
    cvss_version: str | None = None  # "3.1", "4.0", "3.0" ou "2.0"
    cvss_score: float | None = None  # de 0.0 à 10.0
    severity: str | None = None  # CRITICAL | HIGH | MEDIUM | LOW | NONE
    vector: str | None = None  # ex. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cwes: list[str] = field(default_factory=list)  # type de faiblesse, ex. "CWE-79"
    nvd_status: str = ""  # "Analyzed", "Awaiting Analysis", "Not found"...
    published_at: datetime | None = None
    cisa_kev_added: str | None = None  # date d'ajout au catalogue CISA KEV, si exploitée
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
