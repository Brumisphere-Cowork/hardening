# Changelog — brumisphere/hardening

Une entrée par version publiée, la plus récente en tête. Classement des versions :
section « Politique de version » du README.

## 1.2.0 — 2026-10-02

Version mineure.

### Ajouté

- **Interrupteur `svg_restreint`, éteint par défaut.** Allumé, il retire le SVG des types
  acceptés pour tout compte sans `unfiltered_html` (filtre `upload_mimes`, priorité
  `PHP_INT_MAX`, deux arguments). La règle est celle de `get_allowed_mime_types()` :
  l'utilisateur passé par WordPress s'il y en a un, l'utilisateur courant sinon.
- Le retrait du SVG par `televersement` est inchangé, à la priorité 10.

### Raison

Le retrait de `televersement` passe avant les thèmes et les extensions : un thème qui
ajoute le SVG le remet. Constaté sur une reprise, dont le thème réserve le SVG aux
administrateurs pour un logo vectoriel. `svg_restreint` garde ce choix et ferme le SVG
aux autres comptes, quoi qu'ajoutent les extensions.

### Classement

Nouvel interrupteur, éteint par défaut : aucun site ne change de comportement sans le
décider. Mineure, selon la table du README. C'est la deuxième exception au principe
« tous les modules actifs par défaut », après `oembed_auteur`. Il sera allumé à la
prochaine version majeure.

## 1.1.0 — 2026-10-01

Version mineure.

### Ajouté

- **Interrupteur `oembed_auteur`, éteint par défaut.** Allumé, il retire `author_name` et
  `author_url` de la réponse oEmbed d'un contenu (filtre `oembed_response_data`).
  `author_url` est l'adresse de l'archive d'auteur : elle contient l'identifiant de
  connexion, qu'`enumeration` masque partout ailleurs depuis la 1.0.27. Les deux
  interrupteurs sont indépendants.

### Classement

Nouvel interrupteur, éteint par défaut : aucun site ne change de comportement sans le
décider. Mineure, selon la table du README. C'est la première exception au principe « tous
les modules actifs par défaut » : allumer `oembed_auteur` par défaut serait une version
majeure. Il le sera à la prochaine.

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
