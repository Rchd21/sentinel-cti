"""Enrichissement des avis CERT-FR à partir de l'export JSON de chaque avis.

Le flux RSS ne donne qu'un titre et un résumé. La page de chaque avis propose un
export JSON (lien ".../json/") avec les CVE, les systèmes affectés et les risques.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any

import requests

from sentinel.config import settings
from sentinel.db.repository import AdvisoryRepository
from sentinel.ingestion.base import build_session
from sentinel.ingestion.certfr import CVE_RE

log = logging.getLogger(__name__)

SOURCE = "certfr"


@dataclass
class AffectedSystem:
    vendor: str
    product: str
    description: str


@dataclass
class CertFrDetails:
    cves: list[str] = field(default_factory=list)
    affected_systems: list[AffectedSystem] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


@dataclass
class EnrichStats:
    enriched: int = 0
    missing: int = 0
    errors: int = 0

    def __str__(self) -> str:
        return f"{self.enriched} enrichis, {self.missing} sans détail, {self.errors} en erreur"


def json_url(advisory_url: str) -> str:
    """https://.../avis/CERTFR-2026-AVI-1342/ -> https://.../avis/CERTFR-2026-AVI-1342/json/"""
    return advisory_url.rstrip("/") + "/json/"


def _text(value: Any) -> str:
    """Texte nettoyé, ou chaîne vide si la valeur n'est pas du texte."""
    return value.strip() if isinstance(value, str) else ""


def _dicts(value: Any) -> list[dict]:
    """Garde uniquement les éléments qui sont des dictionnaires."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def parse_details(data: dict) -> CertFrDetails:
    """Extrait CVE, systèmes affectés et risques d'un export JSON CERT-FR."""
    # 1. CVE : la liste officielle + un filet de sécurité qui cherche partout dans le JSON.
    listed = [_text(item.get("name")) for item in _dicts(data.get("cves"))]
    found = CVE_RE.findall(json.dumps(data, ensure_ascii=False))
    cves = sorted({cve.upper() for cve in [*listed, *found] if cve})

    # 2. Systèmes affectés : éditeur, produit et versions concernées.
    systems = []
    for item in _dicts(data.get("affected_systems")):
        product = item.get("product") if isinstance(item.get("product"), dict) else {}
        vendor = product.get("vendor") if isinstance(product.get("vendor"), dict) else {}
        systems.append(
            AffectedSystem(
                vendor=_text(vendor.get("name")),
                product=_text(product.get("name")),
                description=_text(item.get("description")),
            )
        )

    # 3. Risques : "Exécution de code arbitraire à distance", "Déni de service"...
    risks = [_text(r.get("description")) for r in _dicts(data.get("risks"))]
    risks = [risk for risk in risks if risk]

    return CertFrDetails(cves=cves, affected_systems=systems, risks=risks)


class CertFrDetailsFetcher:
    def __init__(self, session: requests.Session | None = None, delay: float | None = None) -> None:
        self.session = session or build_session()
        self.delay = settings.http_delay if delay is None else delay

    def fetch(self, advisory_url: str) -> dict | None:
        """Télécharge l'export JSON. Renvoie None si l'avis n'en a pas."""
        resp = self.session.get(json_url(advisory_url), timeout=settings.http_timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError:  # le site a renvoyé une page HTML au lieu du JSON
            return None
        return data if isinstance(data, dict) else None

    def enrich_pending(self, repo: AdvisoryRepository, limit: int = 50) -> EnrichStats:
        """Enrichit les avis pas encore traités, du plus récent au plus ancien."""
        stats = EnrichStats()
        for ref_id, url in repo.pending_details(SOURCE, limit):
            try:
                data = self.fetch(url)
            except requests.RequestException as exc:
                log.warning("[certfr] détail de %s indisponible : %s", ref_id, exc)
                stats.errors += 1
                continue

            if data is None:
                repo.save_details(SOURCE, ref_id, found=False)
                stats.missing += 1
            else:
                details = parse_details(data)
                repo.save_details(
                    SOURCE,
                    ref_id,
                    found=True,
                    cves=details.cves,
                    affected_systems=[asdict(s) for s in details.affected_systems],
                    risks=details.risks,
                )
                stats.enriched += 1
                log.info("[certfr] %s : %d CVE", ref_id, len(details.cves))

            time.sleep(self.delay)  # politesse : on ne sature pas le site
        return stats
