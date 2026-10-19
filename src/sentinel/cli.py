"""Point d'entrée en ligne de commande.

sentinel ingest certfr     # collecte et enregistre les avis CERT-FR
sentinel enrich certfr     # récupère CVE, systèmes affectés et risques de chaque avis
sentinel show CERTFR-2026-AVI-1342   # fiche complète d'un avis
sentinel latest -n 10      # affiche les derniers avis en base
"""

from __future__ import annotations

import argparse
import logging
import sys

from sentinel.db import AdvisoryRepository, get_engine
from sentinel.ingestion import CONNECTORS
from sentinel.ingestion.certfr_details import CertFrDetailsFetcher


def cmd_ingest(args: argparse.Namespace) -> int:
    names = list(CONNECTORS) if args.source == "all" else [args.source]
    repo = AdvisoryRepository(get_engine())
    for name in names:
        advisories = CONNECTORS[name]().run()
        stats = repo.upsert_many(advisories)
        print(f"[{name}] {len(advisories)} collectés -> {stats}")
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    repo = AdvisoryRepository(get_engine())
    stats = CertFrDetailsFetcher().enrich_pending(repo, limit=args.limit)
    print(f"[certfr] détail des avis -> {stats}")
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

    p_enrich = sub.add_parser("enrich", help="récupérer le détail des avis (CVE, systèmes)")
    p_enrich.add_argument("source", choices=["certfr"])
    p_enrich.add_argument("--limit", type=int, default=50)
    p_enrich.set_defaults(func=cmd_enrich)

    p_show = sub.add_parser("show", help="afficher la fiche complète d'un avis")
    p_show.add_argument("ref_id")
    p_show.add_argument("--source", default="certfr")
    p_show.set_defaults(func=cmd_show)

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
