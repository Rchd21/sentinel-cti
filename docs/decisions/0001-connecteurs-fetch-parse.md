# ADR 0001 — Séparer collecte réseau et parsing dans chaque connecteur

- Date : 2026-10-19
- Statut : accepté

## Contexte

Les sources OSINT changent (URL, format, disponibilité). Le domaine du CERT-FR est par
exemple passé de `cert.ssi.gouv.fr` à `cert.cyber.gouv.fr`. Il faut pouvoir tester le code
sans Internet et isoler les pannes d'une source.

## Décision

Chaque connecteur hérite de `Connector` et implémente :

- `fetch_raw()` : seul point de contact réseau, avec reprise automatique (3 essais) ;
- `parse()` : fonction pure, testée sur des fichiers d'exemple dans `tests/fixtures/`.

Un flux en échec est journalisé et ignoré ; les autres continuent. L'écriture en base est
idempotente : clé unique `(source, ref_id)` et empreinte de contenu pour détecter les mises
à jour.

## Conséquences

- Tests rapides et déterministes en CI, test réseau réel marqué `live`.
- Ajouter une source = une classe + une fixture + une ligne dans le registre `CONNECTORS`.
