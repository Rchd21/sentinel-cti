"""Point d'entrée en ligne de commande.

sentinel ingest certfr     # collecte et enregistre les avis CERT-FR
sentinel enrich certfr     # récupère CVE, systèmes affectés et risques de chaque avis
sentinel enrich nvd        # récupère la gravité (CVSS) des CVE citées dans les avis
sentinel show CERTFR-2026-AVI-1342   # fiche complète d'un avis
sentinel cve CVE-2026-24101          # fiche d'une CVE
sentinel match             # avis qui concernent l'inventaire de l'entreprise
sentinel match CERTFR-2026-AVI-1301  # correspondances d'un avis précis
sentinel latest -n 10      # affiche les derniers avis en base
"""

from __future__ import annotations

import argparse
import logging
import sys

from sentinel.db import AdvisoryRepository, get_engine
from sentinel.db.cve_repository import CveRepository, severity_counts
from sentinel.ingestion import CONNECTORS
from sentinel.ingestion.certfr_details import CertFrDetailsFetcher
from sentinel.ingestion.nvd import NvdClient
from sentinel.inventory import (
    DEFAULT_INVENTORY,
    UP_TO_DATE,
    VULNERABLE,
    Match,
    load_inventory,
    match_advisory,
)


def cmd_ingest(args: argparse.Namespace) -> int:
    names = list(CONNECTORS) if args.source == "all" else [args.source]
    repo = AdvisoryRepository(get_engine())
    for name in names:
        advisories = CONNECTORS[name]().run()
        stats = repo.upsert_many(advisories)
        print(f"[{name}] {len(advisories)} collectés -> {stats}")
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    engine = get_engine()
    if args.source == "certfr":
        stats = CertFrDetailsFetcher().enrich_pending(AdvisoryRepository(engine), args.limit)
        print(f"[certfr] détail des avis -> {stats}")
    elif args.source == "nvd":
        stats = NvdClient().enrich_pending(CveRepository(engine), args.limit)
        print(f"[nvd] gravité des CVE -> {stats}")
    return 0


def cmd_cve(args: argparse.Namespace) -> int:
    row = CveRepository(get_engine()).get(args.cve_id.upper())
    if row is None:
        print(f"{args.cve_id} pas encore en base (lancer : sentinel enrich nvd)")
        return 1
    score = f"{row.cvss_score} {row.severity} (CVSS {row.cvss_version})" if row.cvss_score else "-"
    print(f"{row.cve_id}  [{row.nvd_status}]")
    print(f"Gravité  : {score}")
    print(f"Vecteur  : {row.vector or '-'}")
    print(f"Faiblesse: {', '.join(row.cwes or []) or '-'}")
    if row.cisa_kev_added:
        print(f"EXPLOITÉE: ajoutée au catalogue CISA KEV le {row.cisa_kev_added}")
    print(f"\n{row.description}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    row = AdvisoryRepository(get_engine()).get(args.source, args.ref_id)
    if row is None:
        print(f"{args.ref_id} introuvable en base")
        return 1
    print(f"{row.ref_id} - {row.title}\n{row.url}\n")
    print("Risques :", ", ".join(row.risks or []) or "non renseignés")
    print("Systèmes affectés :")
    for system in row.affected_systems or []:
        print(f"  - {system['vendor']} {system['product']} : {system['description']}")
    cves = row.cves or []
    shown = ", ".join(cves[:10]) + (f" ... (+{len(cves) - 10})" if len(cves) > 10 else "")
    print(f"CVE ({len(cves)}) : {shown or 'aucune'}")

    scored = CveRepository(get_engine()).for_ids(cves)
    if scored:
        counts = ", ".join(f"{n} {level}" for level, n in severity_counts(scored).items())
        print(f"\nGravité ({len(scored)}/{len(cves)} CVE notées) : {counts or '-'}")
        for cve in scored[:5]:
            kev = "  EXPLOITÉE (KEV)" if cve.cisa_kev_added else ""
            print(f"  {cve.cve_id:<18} {cve.cvss_score or '-':>4} {cve.severity or ''}{kev}")
    return 0


def print_matches(row, matches: list[Match]) -> None:
    """Affiche un avis et les équipements de l'inventaire qu'il concerne."""
    date = row.published_at.strftime("%Y-%m-%d") if row.published_at else "????-??-??"
    print(f"\n{date}  {row.ref_id}  {row.title[:70]}")
    for m in matches:
        a = m.asset
        print(
            f"  [{m.status:<10}] {a.asset_id} {a.vendor} {a.product} {a.version}"
            f"  ({a.exposure}, criticité {a.criticality}/5, {a.owner})"
        )
        print(f"               -> {m.reason}")


def cmd_match(args: argparse.Namespace) -> int:
    assets = load_inventory(args.inventory)
    repo = AdvisoryRepository(get_engine())

    if args.ref_id:
        row = repo.get("certfr", args.ref_id)
        if row is None:
            print(f"{args.ref_id} introuvable en base")
            return 1
        matches = match_advisory(row.affected_systems, assets)
        if matches:
            print_matches(row, matches)
        else:
            print(f"{row.ref_id} : aucun équipement de l'inventaire concerné")
        return 0

    concerned = vulnerable = 0
    for row in repo.with_affected_systems():
        matches = [
            m for m in match_advisory(row.affected_systems, assets) if m.status != UP_TO_DATE
        ]
        if not matches:
            continue
        concerned += 1
        vulnerable += sum(m.status == VULNERABLE for m in matches)
        print_matches(row, matches)

    print(
        f"\nBilan : {concerned} avis concernent l'inventaire "
        f"({len(assets)} équipements), {vulnerable} correspondances VULNÉRABLES."
    )
    return 0


def cmd_latest(args: argparse.Namespace) -> int:
    repo = AdvisoryRepository(get_engine())
    for row in repo.latest(args.n):
        date = row.published_at.strftime("%Y-%m-%d") if row.published_at else "????-??-??"
        cves = f" [{len(row.cves)} CVE]" if row.cves else ""
        print(f"{date}  {row.ref_id:<22} {row.kind:<8} {row.title[:70]}{cves}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="SentinelCTI")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="collecter une source")
    p_ingest.add_argument("source", choices=[*CONNECTORS, "all"])
    p_ingest.set_defaults(func=cmd_ingest)

    p_enrich = sub.add_parser("enrich", help="enrichir : détail des avis ou gravité des CVE")
    p_enrich.add_argument("source", choices=["certfr", "nvd"])
    p_enrich.add_argument("--limit", type=int, default=50)
    p_enrich.set_defaults(func=cmd_enrich)

    p_cve = sub.add_parser("cve", help="afficher la fiche d'une CVE")
    p_cve.add_argument("cve_id")
    p_cve.set_defaults(func=cmd_cve)

    p_show = sub.add_parser("show", help="afficher la fiche complète d'un avis")
    p_show.add_argument("ref_id")
    p_show.add_argument("--source", default="certfr")
    p_show.set_defaults(func=cmd_show)

    p_match = sub.add_parser("match", help="avis qui concernent l'inventaire de l'entreprise")
    p_match.add_argument("ref_id", nargs="?", help="un avis précis (facultatif)")
    p_match.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    p_match.set_defaults(func=cmd_match)

    p_latest = sub.add_parser("latest", help="derniers avis en base")
    p_latest.add_argument("-n", type=int, default=10)
    p_latest.set_defaults(func=cmd_latest)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
