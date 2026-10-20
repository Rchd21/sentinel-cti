# SentinelCTI

Plateforme de Threat Intelligence augmentée par l'IA pour un acteur de l'énergie :
collecte OSINT, extraction d'IoC, mapping MITRE ATT&CK, priorisation selon le parc et
assistant analyste (RAG) sur LLM local.

> Projet portfolio — sources publiques uniquement, aucun scan ni interaction active avec
> des systèmes tiers. L'entreprise « EnerGrid » et son inventaire sont fictifs.

## Avancement

| Phase | Contenu | Statut |
| --- | --- | --- |
| 0 | Cadrage, personas, KPI | ✅ |
| 1 | Ingestion : CERT-FR (flux RSS + détail des avis) | ✅ |
| 1 | Ingestion : NVD (gravité CVSS des CVE) | ✅ |
| 1 | Ingestion : CISA KEV, EPSS, ThreatFox | ⏳ |
| 2 | Extraction d'IoC | — |
| 3 | Enrichissement, ATT&CK | — |
| 4 | Scoring de priorité | — |
| 5 | Assistant RAG | — |
| 6 | Dashboard, rapport hebdo | — |
| 7 | Industrialisation | — |

## Démarrage rapide

```bash
python -m venv .venv && source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env

sentinel ingest certfr     # collecte les flux CERT-FR (avis, alertes, CTI, IoC, SCADA)
sentinel enrich certfr     # détail de chaque avis : CVE, systèmes affectés, risques
sentinel enrich nvd --limit 100      # gravité CVSS des CVE (clé NVD_API_KEY conseillée)
sentinel show CERTFR-2026-AVI-1342   # fiche complète d'un avis, avec la gravité de ses CVE
sentinel cve CVE-2021-44228          # fiche d'une CVE
sentinel latest -n 10      # derniers avis enregistrés
pytest                     # tests hors ligne
pytest -m live             # test réel contre le CERT-FR (Internet requis)
```

Par défaut la base est un fichier SQLite (`data/sentinel.db`). Pour PostgreSQL :

```bash
docker compose up -d db
pip install -e ".[postgres]"
# dans .env : DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
```

## Architecture

```
src/sentinel/
├── ingestion/   connecteurs (base.py = contrat commun, certfr.py, ...)
├── db/          schéma SQLAlchemy + écriture idempotente
├── models.py    objet Advisory normalisé
└── cli.py       commandes sentinel
```

Choix techniques documentés dans [`docs/decisions/`](docs/decisions/).

## Sources

| Source | Accès | Statut |
| --- | --- | --- |
| CERT-FR | Flux RSS publics ([annuaire](https://cert.cyber.gouv.fr/flux-rss/)) | ✅ |
| NVD | API REST 2.0 | ✅ |
| CISA KEV | JSON | ⏳ |
| FIRST EPSS | API REST | ⏳ |
| abuse.ch ThreatFox | API | ⏳ |
