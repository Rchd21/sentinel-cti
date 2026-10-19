"""Point d'entrée en ligne de commande.

sentinel ingest certfr     # collecte et enregistre les avis CERT-FR
sentinel latest -n 10      # affiche les derniers avis en base
"""

from __future__ import annotations

import argparse
import logging
import sys

from sentinel.db import AdvisoryRepository, get_engine
from sentinel.ingestion import CONNECTORS


def cmd_ingest(args: argparse.Namespace) -> int:
    names = list(CONNECTORS) if args.source == "all" else [args.source]
    repo = AdvisoryRepository(get_engine())
    for name in names:
        advisories = CONNECTORS[name]().run()
        stats = repo.upsert_many(advisories)
        print(f"[{name}] {len(advisories)} collectés -> {stats}")
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
