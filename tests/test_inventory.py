from pathlib import Path

import pytest

from sentinel.cli import main
from sentinel.inventory import (
    DEFAULT_INVENTORY,
    TO_CHECK,
    UP_TO_DATE,
    VULNERABLE,
    Asset,
    is_older,
    load_inventory,
    match_advisory,
    normalize,
    parse_version,
    version_status,
)

ROOT = Path(__file__).parent.parent


def asset(asset_id="A1", vendor="Fortinet", product="FortiGate", version="7.2.8", **kw) -> Asset:
    defaults = dict(
        keywords=["FortiOS", "FortiGate"],
        category="firewall",
        environment="IT",
        exposure="internet",
        criticality=5,
        owner="Réseau",
    )
    defaults.update(kw)
    return Asset(asset_id, vendor, product, version, **defaults)


def system(vendor, product, description) -> dict:
    return {"vendor": vendor, "product": product, "description": description}


# --- outils de base --------------------------------------------------------------


def test_normalize_removes_accents_and_case():
    assert normalize("  Schneider  Électric ") == "schneider electric"


def test_parse_version():
    assert parse_version("7.2.8") == (7, 2, 8)
    assert parse_version("2019 CU14") is None  # pas comparable automatiquement
    assert parse_version("2022") is None


def test_is_older_pads_with_zeros():
    assert is_older((7, 2, 8), (7, 2, 11))  # 8 < 11 numériquement (pas « 8 » > « 1 »)
    assert not is_older((7, 2), (7, 2, 0))
    assert is_older((7, 2), (7, 2, 1))


# --- statut de version -----------------------------------------------------------


def test_version_before_threshold_is_vulnerable():
    status, reason = version_status("7.2.8", "FortiOS versions antérieures à 7.2.11")
    assert status == VULNERABLE
    assert "7.2.11" in reason


def test_version_at_or_after_threshold_is_up_to_date():
    assert version_status("7.2.11", "FortiOS versions antérieures à 7.2.11")[0] == UP_TO_DATE
    assert version_status("7.2.12", "FortiOS versions antérieures à 7.2.11")[0] == UP_TO_DATE


def test_other_branch_is_not_concerned():
    desc = "FortiOS versions 7.4.x antérieures à 7.4.6"
    assert version_status("7.2.8", desc)[0] == UP_TO_DATE  # on est en 7.2, l'avis vise 7.4
    assert version_status("7.4.3", desc)[0] == VULNERABLE


def test_branch_with_capital_xx_like_certfr():
    desc = "Microsoft Edge versions 155.0.4283.XX antérieures à 155.0.4283.60"
    assert version_status("155.0.4283.12", desc)[0] == VULNERABLE
    assert version_status("154.0.4258.37", desc)[0] == UP_TO_DATE


def test_unparseable_versions_need_manual_check():
    assert version_status("2019 CU14", "Exchange Server 2019 CU14 sans le correctif")[0] == TO_CHECK
    assert version_status("7.2.8", "FortiOS toutes versions")[0] == TO_CHECK


# --- correspondance ----------------------------------------------------------------


def test_match_by_vendor_and_keyword():
    matches = match_advisory(
        [system("Fortinet", "FortiOS", "FortiOS versions antérieures à 7.2.11")], [asset()]
    )
    assert len(matches) == 1
    assert matches[0].status == VULNERABLE


def test_no_match_when_vendor_differs():
    # « FortiGate » dans le texte, mais l'éditeur annoncé n'est pas Fortinet
    systems = [system("Autre Éditeur", "Plugin FortiGate", "versions antérieures à 1.0")]
    assert match_advisory(systems, [asset()]) == []


def test_no_match_for_unrelated_product():
    systems = [system("Microsoft", "Edge", "Microsoft Edge versions antérieures à 154.0")]
    assert match_advisory(systems, [asset()]) == []


def test_same_asset_keeps_most_urgent_status():
    systems = [
        system("Fortinet", "FortiOS", "FortiOS versions 7.4.x antérieures à 7.4.6"),  # à jour
        system("Fortinet", "FortiOS", "FortiOS versions 7.2.x antérieures à 7.2.11"),  # vulnérable
    ]
    matches = match_advisory(systems, [asset()])
    assert len(matches) == 1
    assert matches[0].status == VULNERABLE


def test_results_sorted_by_urgency_then_criticality():
    assets = [
        asset("LOW", criticality=2, exposure="interne"),
        asset("HIGH", criticality=5, exposure="internet"),
        asset("CHECK", version="7.2", criticality=5),  # 7.2 < 7.2.11 -> vulnérable aussi
        asset("OK", version="7.2.12", criticality=5),
    ]
    systems = [system("Fortinet", "FortiOS", "FortiOS versions antérieures à 7.2.11")]
    order = [m.asset.asset_id for m in match_advisory(systems, assets)]
    assert order[-1] == "OK"  # à jour en dernier
    assert order.index("HIGH") < order.index("LOW")  # plus critique d'abord


# --- inventaire réel ---------------------------------------------------------------


def test_energrid_inventory_loads():
    assets = load_inventory(ROOT / DEFAULT_INVENTORY)
    assert len(assets) == 25
    assert {a.environment for a in assets} == {"IT", "OT"}
    assert all(a.keywords for a in assets)
    assert all(1 <= a.criticality <= 5 for a in assets)


# --- commande sentinel match -----------------------------------------------------------


@pytest.fixture
def db_with_fortinet(tmp_path, monkeypatch, certfr_sample):
    """Base temporaire avec les avis de test, dont l'avis Fortinet enrichi."""
    from sentinel.config import Settings
    from sentinel.db import AdvisoryRepository, get_engine
    from sentinel.ingestion.certfr import CertFrConnector

    url = f"sqlite:///{tmp_path}/test.db"
    monkeypatch.setattr("sentinel.db.schema.settings", Settings(database_url=url))
    repo = AdvisoryRepository(get_engine(url))
    repo.upsert_many(CertFrConnector(feeds={}).parse("avis", certfr_sample))
    repo.save_details(
        "certfr",
        "CERTFR-2026-AVI-1301",
        found=True,
        affected_systems=[system("Fortinet", "FortiOS", "FortiOS versions antérieures à 7.2.11")],
    )
    return url


def test_cli_match_lists_concerned_advisories(db_with_fortinet, capsys):
    assert main(["match", "--inventory", str(ROOT / DEFAULT_INVENTORY)]) == 0
    out = capsys.readouterr().out
    assert "CERTFR-2026-AVI-1301" in out
    assert "VULNÉRABLE" in out
    assert "A001 Fortinet FortiGate 7.2.8" in out
    assert "Bilan : 1 avis" in out


def test_cli_match_single_advisory_without_match(db_with_fortinet, capsys):
    main(["match", "CERTFR-2026-AVI-1305", "--inventory", str(ROOT / DEFAULT_INVENTORY)])
    assert "aucun équipement" in capsys.readouterr().out


def test_siemens_versions_with_v_prefix():
    desc = "SIMATIC S7-1500 CPU versions antérieures à V3.1.5"
    assert version_status("3.1", desc)[0] == VULNERABLE
    assert version_status("V3.1.5", desc)[0] == UP_TO_DATE


def test_non_standard_versions_are_never_marked_up_to_date():
    # « 22.7R2.4 » ne doit pas être lu « 22.7 » (ce qui donnerait à tort « À JOUR »)
    desc = "Connect Secure versions antérieures à 22.7R2.4"
    assert version_status("22.7", desc)[0] == TO_CHECK
    assert version_status("22.7R2.3", desc)[0] == TO_CHECK


def test_threshold_followed_by_punctuation():
    assert version_status("7.2.8", "versions antérieures à 7.2.11.")[0] == VULNERABLE
    assert version_status("7.2.8", "versions antérieures à 7.2.11, sans correctif")[0] == VULNERABLE
