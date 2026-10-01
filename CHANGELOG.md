# Changelog — brumisphere/hardening

Une entrée par version publiée, la plus récente en tête. Classement des versions :
section « Politique de version » du README.

## 1.0.27 — 2026-10-01

Correctif.

### Corrigé

- **`/?author=1` révélait l'identifiant du compte n° 1 malgré `enumeration`.**
  `redirect_canonical` (cœur, `template_redirect`, priorité 10, enregistré avant les
  mu-plugins) redirigeait en 301 vers l'archive nommée, `/author/{identifiant}/`, avant
  que le blocage, branché à la même priorité, ne pose le 404. Le blocage passe en
  priorité 1, et un filtre `redirect_canonical` refuse toute redirection d'une requête
  d'auteur (variable `author` ou `author_name`).
- **`Hardening::VERSION` valait `1.0.17` depuis la 1.0.17.** Remise à la version publiée.

### Classement

L'effet est observable (`/?author=1` : 301 → 404), mais il ne fait qu'aligner le module
sur ce que le README promettait déjà (« Archives d'auteur en 404 »). Aucun contrôle ne
devient plus strict que son contrat : correctif, pas version majeure.

### Tests

- 5 cas ajoutés, dont 3 en échec sur 1.0.20 avant la correction ; l'amorce vérifie aussi
  `redirect_canonical`.
- `integration.sh` lit `/?author=1` sans suivre les redirections. En les suivant, il ne
  voyait que le 404 final de l'archive nommée.

### Limite connue

oEmbed (`/wp-json/oembed/1.0/embed`) publie `author_name` et `author_url`. Non couvert.

## Versions antérieures (1.0.0 à 1.0.20)

Publiées sans changelog, contrairement à la règle du README. Tags existants : v1.0.0,
v1.0.1, v1.0.3, v1.0.17, v1.0.20. Leur contenu se lit dans l'historique du dépôt de
l'usine, sous `ressources/artefacts/brumisphere-hardening/`.
