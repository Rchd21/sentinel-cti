from datetime import UTC, datetime

import pytest
import requests

from sentinel.ingestion.certfr import DEFAULT_FEEDS, CertFrConnector, clean_html


@pytest.fixture
def connector() -> CertFrConnector:
    return CertFrConnector(feeds={"avis": "https://example.invalid/feed/"})


def test_parse_extracts_identified_items_only(connector, certfr_sample):
    items = connector.parse("avis", certfr_sample)
    assert [a.ref_id for a in items] == [
        "CERTFR-2026-AVI-1301",
        "CERTFR-2026-AVI-1305",
        "CERTFR-2026-ALE-014",
    ]


def test_parse_kind_comes_from_identifier(connector, certfr_sample):
    kinds = {a.ref_id: a.kind for a in connector.parse("avis", certfr_sample)}
    assert kinds["CERTFR-2026-AVI-1301"] == "avis"
    assert kinds["CERTFR-2026-ALE-014"] == "alerte"


def test_parse_cves_are_normalized_and_deduplicated(connector, certfr_sample):
    first = connector.parse("avis", certfr_sample)[0]
    assert first.cves == ["CVE-2026-24101", "CVE-2026-24102"]


def test_parse_date_is_utc(connector, certfr_sample):
    first = connector.parse("avis", certfr_sample)[0]
    assert first.published_at == datetime(2026, 10, 12, 12, 5, tzinfo=UTC)


def test_parse_summary_has_no_html(connector, certfr_sample):
    first = connector.parse("avis", certfr_sample)[0]
    assert "<p>" not in first.summary
    assert first.summary.startswith("De multiples vulnérabilités")


def test_parse_rejects_garbage(connector):
    with pytest.raises(ValueError):
        connector.parse("avis", b"ceci n'est pas du XML <<<")


def test_clean_html():
    assert clean_html("<p>A&nbsp;&amp; B</p>\n  C") == "A & B C"


def test_run_survives_a_failing_feed(certfr_sample):
    """Un flux en panne ne doit pas bloquer les autres."""

    class FakeResponse:
        def __init__(self, content: bytes, ok: bool):
            self.content, self.ok = content, ok

        def raise_for_status(self):
            if not self.ok:
                raise requests.HTTPError("503")

    class FakeSession:
        def get(self, url, timeout):
            return FakeResponse(certfr_sample, ok="good" in url)

    conn = CertFrConnector(
        feeds={"a": "https://good.invalid/", "b": "https://bad.invalid/"},
        session=FakeSession(),
    )
    assert len(conn.run()) == 3


@pytest.mark.live
def test_live_certfr_feed():
    """Lancer avec : pytest -m live (nécessite Internet)."""
    items = CertFrConnector(feeds={"avis": DEFAULT_FEEDS["avis"]}).run()
    assert items, "aucun avis reçu : vérifier l'URL du flux"
    assert all(a.ref_id.startswith("CERTFR-") for a in items)
