"""Connecteur NVD (National Vulnerability Database, NIST) : gravité de chaque CVE.

API CVE 2.0 : https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-AAAA-NNNN
Quotas : 5 requêtes / 30 s sans clé, 50 / 30 s avec une clé gratuite (en-tête "apiKey").
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import requests

from sentinel.config import settings
from sentinel.db.cve_repository import CveRepository
from sentinel.ingestion.base import build_session
from sentinel.models import CveRecord

log = logging.getLogger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Pause entre deux requêtes pour rester sous le quota (avec une marge).
DELAY_WITH_KEY = 0.7  # 50 requêtes / 30 s  -> 0,6 s minimum
DELAY_WITHOUT_KEY = 6.5  # 5 requêtes / 30 s -> 6 s minimum

# Ordre de préférence des versions CVSS. La 3.1 est la plus répandue :
# elle rend les scores comparables entre eux. Les autres servent de secours.
CVSS_PREFERENCE = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


@dataclass
class NvdStats:
    scored: int = 0
    unscored: int = 0
    missing: int = 0
    errors: int = 0

    def __str__(self) -> str:
        return (
            f"{self.scored} notées, {self.unscored} sans score pour l'instant, "
            f"{self.missing} inconnues de la NVD, {self.errors} en erreur"
        )


def _parse_date(value: str | None) -> datetime | None:
    """'2026-10-12T14:15:09.123' -> datetime en UTC (la NVD donne l'heure UTC sans fuseau)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def pick_cvss(metrics: dict) -> tuple[str | None, float | None, str | None, str | None]:
    """Choisit le meilleur score CVSS disponible : (version, score, gravité, vecteur)."""
    for key, version in CVSS_PREFERENCE:
        entries = [e for e in metrics.get(key) or [] if isinstance(e, dict)]
        if not entries:
            continue
        # "Primary" = score calculé par la NVD elle-même ; sinon celui de l'éditeur.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        # En CVSS 2.0, la gravité est rangée à côté de cvssData, pas dedans.
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return version, float(score), (severity or "").upper() or None, data.get("vectorString")
    return None, None, None, None


def parse_cve(item: dict) -> CveRecord:
    """Transforme un élément 'vulnerabilities[].cve' de la NVD en CveRecord."""
    descriptions = item.get("descriptions") or []
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    version, score, severity, vector = pick_cvss(item.get("metrics") or {})

    cwes = sorted(
        {
            d.get("value", "")
            for weakness in item.get("weaknesses") or []
            for d in weakness.get("description") or []
            if d.get("value", "").startswith("CWE-")
        }
    )

    return CveRecord(
        cve_id=item["id"],
        description=description.strip(),
        cvss_version=version,
        cvss_score=score,
        severity=severity,
        vector=vector,
        cwes=cwes,
        nvd_status=item.get("vulnStatus", ""),
        published_at=_parse_date(item.get("published")),
        cisa_kev_added=item.get("cisaExploitAdd"),
    )


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        session: requests.Session | None = None,
        delay: float | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else settings.nvd_api_key
        # La NVD répond 403 quand on dépasse le quota : on réessaie aussi dans ce cas.
        self.session = session or build_session(extra_retry_statuses=(403,))
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key
        if delay is None:
            delay = DELAY_WITH_KEY if self.api_key else DELAY_WITHOUT_KEY
        self.delay = delay

    def fetch(self, cve_id: str) -> CveRecord | None:
        """Fiche d'une CVE, ou None si la NVD ne la connaît pas (encore)."""
        resp = self.session.get(API_URL, params={"cveId": cve_id}, timeout=settings.http_timeout)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        vulnerabilities = resp.json().get("vulnerabilities") or []
        if not vulnerabilities:
            return None
        return parse_cve(vulnerabilities[0]["cve"])

    def enrich_pending(self, repo: CveRepository, limit: int = 100) -> NvdStats:
        """Note les CVE citées dans les avis qui n'ont pas encore de fiche."""
        stats = NvdStats()
        pending = repo.pending(limit)
        if not self.api_key and pending:
            log.warning(
                "[nvd] pas de clé API : %d CVE à ~%.1f s chacune (~%d s au total). "
                "Clé gratuite : https://nvd.nist.gov/developers/request-an-api-key",
                len(pending),
                self.delay,
                round(len(pending) * self.delay),
            )

        for i, cve_id in enumerate(pending):
            if i:
                time.sleep(self.delay)  # respect du quota
            try:
                record = self.fetch(cve_id)
            except (requests.RequestException, ValueError, KeyError) as exc:
                log.warning("[nvd] %s indisponible : %s", cve_id, exc)
                stats.errors += 1
                continue

            if record is None:
                record = CveRecord(cve_id=cve_id, nvd_status="Not found")
                stats.missing += 1
            elif record.cvss_score is None:
                stats.unscored += 1
            else:
                stats.scored += 1
            repo.save(record)
            log.info("[nvd] %s : %s %s", cve_id, record.cvss_score or "-", record.severity or "")
        return stats
