import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests

from sentinel.db import AdvisoryRepository, get_engine
from sentinel.db.cve_repository import CveRepository, severity_counts
from sentinel.ingestion.certfr import CertFrConnector
from sentinel.ingestion.nvd import API_URL, NvdClient, parse_cve, pick_cvss
from sentinel.models import CveRecord

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def nvd_response() -> dict:
    return json.loads((FIXTURES / "nvd_cve_sample.json").read_text(encoding="utf-8"))


@pytest.fixture
def nvd_cve(nvd_response) -> dict:
    return nvd_response["vulnerabilities"][0]["cve"]


@pytest.fixture
def engine(certfr_sample):
    """Base en mémoire avec les 3 avis du faux flux (4 CVE citées au total)."""
    engine = get_engine("sqlite:///:memory:")
    AdvisoryRepository(engine).upsert_many(CertFrConnector(feeds={}).parse("avis", certfr_sample))
    return engine


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code, self.payload = status_code, payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return self.payload


class FakeSession:
    """Fausse NVD : répond selon le paramètre cveId."""

    def __init__(self, by_cve: dict[str, FakeResponse]):
        self.by_cve, self.headers, self.calls = by_cve, {}, []

    def get(self, url, params, timeout):
        assert url == API_URL
        self.calls.append(params["cveId"])
        return self.by_cve.get(params["cveId"], FakeResponse(200, {"vulnerabilities": []}))


# --- parsing ---------------------------------------------------------------------


def test_parse_prefers_nvd_primary_cvss31(nvd_cve):
    record = parse_cve(nvd_cve)
    assert (record.cvss_version, record.cvss_score, record.severity) == ("3.1", 9.8, "CRITICAL")
    assert record.vector.endswith("A:H")  # celui de la NVD, pas celui de l'éditeur


def test_parse_english_description_cwe_and_kev(nvd_cve):
    record = parse_cve(nvd_cve)
    assert record.description.startswith("An out-of-bounds write")
    assert record.cwes == ["CWE-787"]  # dédoublonnée, "NVD-CWE-noinfo" écartée
    assert record.cisa_kev_added == "2026-10-14"
    assert record.nvd_status == "Analyzed"
    assert record.published_at == datetime(2026, 10, 12, 14, 15, 9, 123000, tzinfo=UTC)


def test_pick_cvss_falls_back_to_v40_then_v2():
    v40 = {"cvssMetricV40": [{"cvssData": {"baseScore": 8.7, "baseSeverity": "HIGH"}}]}
    assert pick_cvss(v40)[:3] == ("4.0", 8.7, "HIGH")

    # En CVSS 2.0, la gravité est hors de cvssData
    v2 = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}
    assert pick_cvss(v2)[:3] == ("2.0", 5.0, "MEDIUM")


def test_pick_cvss_without_any_score():
    assert pick_cvss({}) == (None, None, None, None)


# --- client ----------------------------------------------------------------------


def test_api_key_goes_in_header():
    session = FakeSession({})
    client = NvdClient(api_key="ma-cle", session=session)
    assert session.headers["apiKey"] == "ma-cle"
    assert client.delay < 1  # avec clé : quota de 50 requêtes / 30 s


def test_no_api_key_means_slow_and_polite():
    client = NvdClient(api_key="", session=FakeSession({}))
    assert "apiKey" not in client.session.headers
    assert client.delay >= 6  # sans clé : 5 requêtes / 30 s


def test_fetch_unknown_cve_returns_none():
    assert NvdClient(api_key="", session=FakeSession({}), delay=0).fetch("CVE-2026-1") is None


# --- tournée d'enrichissement ----------------------------------------------------


def test_pending_lists_cves_from_recent_advisories_first(engine):
    pending = CveRepository(engine).pending()
    assert pending == ["CVE-2026-20001", "CVE-2026-31337", "CVE-2026-24101", "CVE-2026-24102"]
    assert CveRepository(engine).pending(limit=2) == ["CVE-2026-20001", "CVE-2026-31337"]


def test_enrich_pending_saves_and_counts(engine, nvd_response):
    session = FakeSession(
        {
            "CVE-2026-24101": FakeResponse(200, nvd_response),
            "CVE-2026-31337": FakeResponse(503),
        }
    )
    repo = CveRepository(engine)
    stats = NvdClient(api_key="k", session=session, delay=0).enrich_pending(repo)

    assert (stats.scored, stats.missing, stats.errors) == (1, 2, 1)
    assert repo.get("CVE-2026-24101").cvss_score == 9.8
    assert repo.get("CVE-2026-20001").nvd_status == "Not found"
    # La CVE en erreur réseau sera retentée ; les autres ne sont plus à faire
    assert repo.pending() == ["CVE-2026-31337"]


def test_unscored_cve_is_rechecked_after_a_week(engine):
    repo = CveRepository(engine)
    old = datetime.now(UTC) - timedelta(days=8)
    repo.save(CveRecord(cve_id="CVE-2026-24102", nvd_status="Awaiting Analysis", fetched_at=old))
    repo.save(CveRecord(cve_id="CVE-2026-24101", nvd_status="Awaiting Analysis"))

    pending = repo.pending()
    assert "CVE-2026-24102" in pending  # vue il y a 8 jours sans score : on relit
    assert "CVE-2026-24101" not in pending  # vue à l'instant : on attend


def test_for_ids_sorted_by_score_and_severity_counts(engine):
    repo = CveRepository(engine)
    repo.save(CveRecord(cve_id="CVE-A", cvss_score=5.3, severity="MEDIUM"))
    repo.save(CveRecord(cve_id="CVE-B", cvss_score=9.8, severity="CRITICAL"))
    repo.save(CveRecord(cve_id="CVE-C", cvss_score=7.5, severity="HIGH"))

    rows = repo.for_ids(["CVE-A", "CVE-B", "CVE-C", "CVE-INCONNUE"])
    assert [r.cve_id for r in rows] == ["CVE-B", "CVE-C", "CVE-A"]
    assert severity_counts(rows) == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}


@pytest.mark.live
def test_live_nvd_known_cve():
    """pytest -m live : Log4Shell, CVE célèbre notée 10.0."""
    record = NvdClient(delay=0).fetch("CVE-2021-44228")
    assert record is not None
    assert record.cvss_score == 10.0
    assert record.cisa_kev_added  # exploitée et listée par la CISA


def test_pending_with_zero_limit_is_empty(engine):
    assert CveRepository(engine).pending(limit=0) == []
