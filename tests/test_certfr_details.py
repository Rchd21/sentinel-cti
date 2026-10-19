import json
from pathlib import Path

import pytest
import requests

from sentinel.db import AdvisoryRepository, get_engine
from sentinel.ingestion.certfr import CertFrConnector
from sentinel.ingestion.certfr_details import CertFrDetailsFetcher, json_url, parse_details

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def details_sample() -> dict:
    return json.loads((FIXTURES / "certfr_details_sample.json").read_text(encoding="utf-8"))


@pytest.fixture
def repo(certfr_sample) -> AdvisoryRepository:
    """Base en mémoire contenant les 3 avis du faux flux RSS."""
    repo = AdvisoryRepository(get_engine("sqlite:///:memory:"))
    repo.upsert_many(CertFrConnector(feeds={}).parse("avis", certfr_sample))
    return repo


class FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, html: bool = False):
        self.status_code, self.payload, self.html = status_code, payload, html

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        if self.html:
            raise ValueError("pas du JSON")
        return self.payload


class FakeSession:
    """Répond selon l'URL demandée, sans aller sur Internet."""

    def __init__(self, responses: dict[str, FakeResponse]):
        self.responses = responses
        self.calls: list[str] = []

    def get(self, url, timeout):
        self.calls.append(url)
        for fragment, response in self.responses.items():
            if fragment in url:
                return response
        return FakeResponse(404)


# --- parse_details ---------------------------------------------------------------


def test_json_url():
    assert (
        json_url("https://x.fr/avis/CERTFR-2026-AVI-1/")
        == "https://x.fr/avis/CERTFR-2026-AVI-1/json/"
    )
    assert (
        json_url("https://x.fr/avis/CERTFR-2026-AVI-1")
        == "https://x.fr/avis/CERTFR-2026-AVI-1/json/"
    )


def test_parse_cves_from_list_and_anywhere_in_document(details_sample):
    cves = parse_details(details_sample).cves
    assert cves == ["CVE-2026-24101", "CVE-2026-24102", "CVE-2026-24199"]


def test_parse_affected_systems(details_sample):
    systems = parse_details(details_sample).affected_systems
    assert len(systems) == 2  # l'élément mal formé est ignoré
    assert systems[0].vendor == "Fortinet"
    assert systems[0].product == "FortiOS"
    assert "7.2.11" in systems[0].description


def test_parse_risks_skips_empty(details_sample):
    assert parse_details(details_sample).risks == [
        "Exécution de code arbitraire à distance",
        "Contournement de la politique de sécurité",
    ]


def test_parse_survives_unexpected_structure():
    details = parse_details({"cves": "pas une liste", "affected_systems": None})
    assert (details.cves, details.affected_systems, details.risks) == ([], [], [])


# --- fetch -----------------------------------------------------------------------


def test_fetch_returns_none_when_no_json():
    fetcher = CertFrDetailsFetcher(
        session=FakeSession({"AVI-2": FakeResponse(200, html=True)}), delay=0
    )
    assert fetcher.fetch("https://x.fr/avis/CERTFR-2026-AVI-1/") is None  # 404
    assert fetcher.fetch("https://x.fr/avis/CERTFR-2026-AVI-2/") is None  # page HTML


# --- enrich_pending --------------------------------------------------------------


def test_enrich_pending_saves_details(repo, details_sample):
    session = FakeSession({"AVI-1301": FakeResponse(200, payload=details_sample)})
    stats = CertFrDetailsFetcher(session=session, delay=0).enrich_pending(repo)

    assert (stats.enriched, stats.missing, stats.errors) == (1, 2, 0)
    row = repo.get("certfr", "CERTFR-2026-AVI-1301")
    assert "CVE-2026-24199" in row.cves
    assert row.affected_systems[0]["product"] == "FortiOS"
    assert row.risks[0] == "Exécution de code arbitraire à distance"


def test_enrich_pending_skips_already_processed(repo, details_sample):
    session = FakeSession({"AVI-1301": FakeResponse(200, payload=details_sample)})
    fetcher = CertFrDetailsFetcher(session=session, delay=0)
    fetcher.enrich_pending(repo)
    calls_after_first_run = len(session.calls)

    stats = fetcher.enrich_pending(repo)
    assert (stats.enriched, stats.missing) == (0, 0)
    assert len(session.calls) == calls_after_first_run  # aucune nouvelle requête


def test_enrich_pending_counts_network_errors(repo):
    session = FakeSession({"AVI-1301": FakeResponse(503)})
    stats = CertFrDetailsFetcher(session=session, delay=0).enrich_pending(repo)
    assert stats.errors == 1
    # l'avis en erreur reste à traiter pour la prochaine fois
    assert "CERTFR-2026-AVI-1301" in [ref for ref, _ in repo.pending_details("certfr")]


def test_new_rss_collection_keeps_enriched_cves(repo, details_sample, certfr_sample):
    session = FakeSession({"AVI-1301": FakeResponse(200, payload=details_sample)})
    CertFrDetailsFetcher(session=session, delay=0).enrich_pending(repo)

    items = CertFrConnector(feeds={}).parse("avis", certfr_sample)
    items[0].summary += " Mise à jour."
    repo.upsert_many(items)

    row = repo.get("certfr", "CERTFR-2026-AVI-1301")
    assert "CVE-2026-24199" in row.cves  # CVE de l'enrichissement conservée
    assert row.details_fetched_at is None  # avis modifié : détail à relire


@pytest.mark.live
def test_live_certfr_details():
    """pytest -m live : lit le vrai export JSON d'un avis récent."""
    advisories = CertFrConnector(feeds={"avis": "https://cert.cyber.gouv.fr/avis/feed/"}).run()
    data = CertFrDetailsFetcher(delay=0).fetch(advisories[0].url)
    assert data is not None, "pas d'export JSON : vérifier l'URL .../json/"
    details = parse_details(data)
    assert details.cves or details.affected_systems, f"champs inattendus : {list(data)}"
