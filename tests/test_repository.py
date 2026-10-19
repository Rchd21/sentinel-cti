from sentinel.db import AdvisoryRepository, get_engine
from sentinel.ingestion.certfr import CertFrConnector


def make_repo() -> AdvisoryRepository:
    return AdvisoryRepository(get_engine("sqlite:///:memory:"))


def test_upsert_is_idempotent(certfr_sample):
    repo = make_repo()
    items = CertFrConnector(feeds={}).parse("avis", certfr_sample)

    first = repo.upsert_many(items)
    second = repo.upsert_many(items)

    assert (first.new, first.updated, first.unchanged) == (3, 0, 0)
    assert (second.new, second.updated, second.unchanged) == (0, 0, 3)


def test_upsert_detects_updated_content(certfr_sample):
    repo = make_repo()
    items = CertFrConnector(feeds={}).parse("avis", certfr_sample)
    repo.upsert_many(items)

    items[0].summary += " Mise à jour : correctif disponible."
    stats = repo.upsert_many(items)
    assert (stats.new, stats.updated, stats.unchanged) == (0, 1, 2)


def test_duplicates_across_feeds_are_merged(certfr_sample):
    repo = make_repo()
    conn = CertFrConnector(feeds={})
    items = conn.parse("avis", certfr_sample) + conn.parse("scada", certfr_sample)
    assert repo.upsert_many(items).new == 3


def test_latest_orders_by_publication_date(certfr_sample):
    repo = make_repo()
    repo.upsert_many(CertFrConnector(feeds={}).parse("avis", certfr_sample))
    assert [r.ref_id for r in repo.latest(2)] == ["CERTFR-2026-ALE-014", "CERTFR-2026-AVI-1305"]
