"""Inventaire de l'entreprise et correspondance avec les systèmes affectés des avis.

Question à laquelle répond ce module : « cette alerte nous concerne-t-elle ? »
1. Utilise-t-on ce produit ?        -> même éditeur + un mot-clé du produit
2. Notre version est-elle touchée ? -> comparaison avec « versions antérieures à X »
"""

from __future__ import annotations

import csv
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

DEFAULT_INVENTORY = Path("data/inventory/energrid_assets.csv")

# Statuts possibles d'une correspondance, du plus urgent au moins urgent
VULNERABLE = "VULNÉRABLE"
TO_CHECK = "À VÉRIFIER"
UP_TO_DATE = "À JOUR"
STATUS_ORDER = {VULNERABLE: 0, TO_CHECK: 1, UP_TO_DATE: 2}
EXPOSURE_ORDER = {"internet": 0, "interne": 1, "isole": 2}

# « antérieures à 7.2.11 » -> 7.2.11 ; « antérieures à V3.1.5 » -> V3.1.5 ;
# « antérieures à 22.7R2.4 » -> 22.7R2.4 (capturé en entier pour ne pas le lire « 22.7 »)
BEFORE_RE = re.compile(r"ant[ée]rieures?\s+(?:à|a)\s+(v?\d[\w.\-]*\w|v?\d)", re.IGNORECASE)
# « versions 7.2.x antérieures à ... »  -> branche 7.2
BRANCH_RE = re.compile(r"(\d+(?:\.\d+)*)\.x+\b", re.IGNORECASE)
# Version purement numérique : « 7.2.8 », « V3.1.5 » (mais pas « 2019 CU14 » ni « 22.7R2 »)
VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)+)$", re.IGNORECASE)


@dataclass
class Asset:
    asset_id: str
    vendor: str
    product: str
    version: str
    keywords: list[str]
    category: str
    environment: str  # IT ou OT (informatique industrielle)
    exposure: str  # internet | interne | isole
    criticality: int  # 1 (faible) à 5 (vital)
    owner: str


@dataclass
class Match:
    asset: Asset
    system: dict  # système affecté de l'avis : {"vendor", "product", "description"}
    status: str  # VULNÉRABLE | À VÉRIFIER | À JOUR
    reason: str


def normalize(text: str) -> str:
    """'Schneider Électric' -> 'schneider electric' : sans accents, minuscules, espaces simples."""
    text = unicodedata.normalize("NFKD", text or "")
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = re.sub(r"[^a-z0-9/&.+-]+", " ", text.lower())
    return text.strip()


def load_inventory(path: Path | str = DEFAULT_INVENTORY) -> list[Asset]:
    """Lit le CSV d'inventaire et renvoie une liste d'Asset."""
    with open(path, newline="", encoding="utf-8") as f:
        return [
            Asset(
                asset_id=row["asset_id"],
                vendor=row["vendor"],
                product=row["product"],
                version=row["version"].strip(),
                keywords=[k.strip() for k in row["keywords"].split(";") if k.strip()],
                category=row["category"],
                environment=row["environment"],
                exposure=row["exposure"],
                criticality=int(row["criticality"]),
                owner=row["owner"],
            )
            for row in csv.DictReader(f)
        ]


def parse_version(version: str) -> tuple[int, ...] | None:
    """'7.2.8' -> (7, 2, 8). None si la version n'est pas purement numérique."""
    found = VERSION_RE.match(version.strip())
    if not found:
        return None
    return tuple(int(part) for part in found.group(1).split("."))


def is_older(version: tuple[int, ...], threshold: tuple[int, ...]) -> bool:
    """Compare deux versions en complétant la plus courte par des zéros : 7.2 == 7.2.0."""
    size = max(len(version), len(threshold))
    version = version + (0,) * (size - len(version))
    threshold = threshold + (0,) * (size - len(threshold))
    return version < threshold


def version_status(asset_version: str, description: str) -> tuple[str, str]:
    """Notre version est-elle dans la plage touchée décrite par le CERT-FR ?"""
    ours = parse_version(asset_version)
    threshold_text = BEFORE_RE.search(description)
    if ours is None or threshold_text is None:
        return TO_CHECK, f"version {asset_version} à comparer manuellement"

    threshold = parse_version(threshold_text.group(1))
    if threshold is None:
        # Format non standard (ex. « 22.7R2.4 ») : mieux vaut vérifier que se tromper
        return TO_CHECK, f"format de version non standard ({threshold_text.group(1)})"

    branch = BRANCH_RE.search(description)
    if branch:
        branch_prefix = tuple(int(p) for p in branch.group(1).split("."))
        if ours[: len(branch_prefix)] != branch_prefix:
            # Ex. l'avis vise la branche 7.4.x et nous sommes en 7.2.x
            return UP_TO_DATE, f"branche {asset_version} non concernée ({branch.group(0)})"

    if is_older(ours, threshold):
        return VULNERABLE, f"{asset_version} < {threshold_text.group(1)} : mise à jour requise"
    return UP_TO_DATE, f"{asset_version} >= {threshold_text.group(1)}"


def system_matches_asset(system: dict, asset: Asset) -> bool:
    """Le système affecté désigne-t-il ce produit de l'inventaire ?"""
    vendor = normalize(system.get("vendor", ""))
    if vendor and normalize(asset.vendor) not in vendor and vendor not in normalize(asset.vendor):
        return False
    text = normalize(f"{system.get('product', '')} {system.get('description', '')}")
    return any(normalize(keyword) in text for keyword in asset.keywords)


def match_advisory(affected_systems: list[dict], assets: list[Asset]) -> list[Match]:
    """Toutes les correspondances entre les systèmes d'un avis et l'inventaire.

    Un même équipement peut apparaître dans plusieurs lignes de l'avis (une par branche
    de versions) : on garde pour lui le statut le plus urgent.
    """
    best: dict[str, Match] = {}
    for system in affected_systems or []:
        for asset in assets:
            if not system_matches_asset(system, asset):
                continue
            status, reason = version_status(asset.version, system.get("description", ""))
            current = best.get(asset.asset_id)
            if current is None or STATUS_ORDER[status] < STATUS_ORDER[current.status]:
                best[asset.asset_id] = Match(asset, system, status, reason)

    return sorted(
        best.values(),
        key=lambda m: (
            STATUS_ORDER[m.status],
            -m.asset.criticality,
            EXPOSURE_ORDER.get(m.asset.exposure, 9),
        ),
    )
