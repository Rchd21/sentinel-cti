"""Connecteur CERT-FR (ANSSI) via ses flux RSS publics.

Annuaire des flux : https://cert.cyber.gouv.fr/flux-rss/
(l'ancien domaine cert.ssi.gouv.fr redirige vers cert.cyber.gouv.fr)
"""

from __future__ import annotations

import calendar
import html
import logging
import re
from datetime import UTC, datetime

import feedparser
import requests

from sentinel.config import settings
from sentinel.ingestion.base import Connector
from sentinel.models import Advisory

log = logging.getLogger(__name__)

BASE_URL = "https://cert.cyber.gouv.fr"

# Flux suivis par défaut. "scada" est clé pour un acteur de l'énergie.
DEFAULT_FEEDS: dict[str, str] = {
    "avis": f"{BASE_URL}/avis/feed/",
    "alerte": f"{BASE_URL}/alerte/feed/",
    "cti": f"{BASE_URL}/cti/feed/",
    "ioc": f"{BASE_URL}/ioc/feed/",
    "scada": f"{BASE_URL}/feed/scada/",
}

# CERTFR-2026-AVI-1342, CERTFR-2026-ALE-013, CERTFR-2025-CTI-008 ...
REF_RE = re.compile(r"CERTFR-\d{4}-[A-Z]{3}-\d{3,4}")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")

# Le type est porté par le code de l'identifiant, plus fiable que le flux
# (le flux "scada" mélange avis et alertes).
KIND_BY_CODE = {
    "AVI": "avis",
    "ALE": "alerte",
    "CTI": "cti",
    "IOC": "ioc",
    "DUR": "dur",
    "ACT": "actualite",
}


def clean_html(text: str) -> str:
    """Retire les balises HTML et normalise les espaces."""
    text = html.unescape(TAG_RE.sub(" ", text or ""))
    return re.sub(r"\s+", " ", text).strip()


def to_datetime(entry: feedparser.FeedParserDict) -> datetime | None:
    """Date de publication en UTC (feedparser fournit un struct_time UTC)."""
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return None
    return datetime.fromtimestamp(calendar.timegm(parsed), tz=UTC)


class CertFrConnector(Connector):
    name = "certfr"

    def __init__(
        self,
        feeds: dict[str, str] | None = None,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(session)
        self.feeds = feeds or DEFAULT_FEEDS

    def fetch_raw(self) -> dict[str, bytes]:
        raw: dict[str, bytes] = {}
        for key, url in self.feeds.items():
            try:
                resp = self.session.get(url, timeout=settings.http_timeout)
                resp.raise_for_status()
                raw[key] = resp.content
            except requests.RequestException as exc:
                log.warning("[certfr] flux %s indisponible (%s) : %s", key, url, exc)
        return raw

    def parse(self, key: str, raw: bytes) -> list[Advisory]:
        feed = feedparser.parse(raw)
        if feed.bozo and not feed.entries:
            raise ValueError(f"flux {key} illisible : {feed.bozo_exception}")

        advisories: list[Advisory] = []
        for entry in feed.entries:
            title = clean_html(entry.get("title", ""))
            url = entry.get("link", "")
            summary = clean_html(entry.get("summary", ""))

            match = REF_RE.search(" ".join([url, title, entry.get("id", "")]))
            if not match:
                log.debug("[certfr] élément sans identifiant ignoré : %s", title)
                continue
            ref_id = match.group(0)
            kind = KIND_BY_CODE.get(ref_id.split("-")[2], key)

            # Extraction simple des CVE ; l'extraction complète d'IoC = Phase 2.
            cves = sorted({c.upper() for c in CVE_RE.findall(f"{title} {summary}")})

            advisories.append(
                Advisory(
                    source=self.name,
                    ref_id=ref_id,
                    kind=kind,
                    title=title,
                    url=url,
                    published_at=to_datetime(entry),
                    summary=summary,
                    cves=cves,
                )
            )
        return advisories
