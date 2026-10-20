"""Contrat commun à tous les connecteurs de sources OSINT.

Chaque connecteur sépare deux étapes :
- fetch_raw() : récupère les données brutes (réseau) ;
- parse()     : transforme le brut en objets Advisory (pur, donc testable hors ligne).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from sentinel.config import settings
from sentinel.models import Advisory

log = logging.getLogger(__name__)


RETRY_STATUSES = (429, 500, 502, 503, 504)


def build_session(extra_retry_statuses: tuple[int, ...] = ()) -> requests.Session:
    """Session HTTP avec User-Agent identifiable et reprise automatique sur erreur."""
    session = requests.Session()
    session.headers["User-Agent"] = settings.user_agent
    retry = Retry(
        total=3,
        backoff_factor=2,  # 2 s, 4 s, 8 s
        status_forcelist=RETRY_STATUSES + extra_retry_statuses,
        allowed_methods=("GET",),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


class Connector(ABC):
    """Classe de base : une source = une sous-classe."""

    name: str = "base"

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or build_session()

    @abstractmethod
    def fetch_raw(self) -> dict[str, bytes]:
        """Retourne {clé de flux: contenu brut}."""

    @abstractmethod
    def parse(self, key: str, raw: bytes) -> list[Advisory]:
        """Transforme le contenu brut d'un flux en avis normalisés."""

    def run(self) -> list[Advisory]:
        """Collecte complète. Un flux en échec n'empêche pas les autres."""
        advisories: list[Advisory] = []
        for key, raw in self.fetch_raw().items():
            try:
                items = self.parse(key, raw)
            except Exception:  # noqa: BLE001 - on journalise et on continue
                log.exception("[%s] échec du parsing du flux %s", self.name, key)
                continue
            log.info("[%s] flux %s : %d éléments", self.name, key, len(items))
            advisories.extend(items)
        return advisories
