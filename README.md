# brumisphere/hardening

Durcissement WordPress partagé de Brumisphère.

**Il est actif quel que soit le thème, et ne connaît aucun site en particulier.**

---

## Ce qu'il fait

| Module | Rôle |
|---|---|
| `Hardening` | Point d'entrée, résolution des interrupteurs |
| `Entetes` | En-têtes de sécurité HTTP sur les réponses publiques |
| `Divulgation` | Version de WordPress, liens de découverte, XML-RPC, message de connexion |
| `Enumeration` | Archives d'auteur et point REST des utilisateurs |
| `Fichiers` | Éditeur de code de l'administration |
| `Televersement` | Extensions exécutables et SVG dans la médiathèque |

## Ce qu'il ne fait pas

- **Aucune présentation, aucune sortie visible.** Le site doit s'afficher exactement
  pareil, module actif ou non.
- **Aucun type de contenu, aucune taxonomie.** Ce sont des structures de contenu : elles
  vont dans le mu-plugin propre au site.
- **Aucune page de réglages.** Pas d'interface signifie pas de `$_POST` à valider, donc
  aucune surface d'attaque ajoutée par le durcissement lui-même. La configuration passe
  par du code.
- **Aucune limitation des tentatives de connexion.** Elle exige un stockage, se contourne
  dès qu'un intermédiaire masque l'adresse réelle, et donne un sentiment de sécurité
  disproportionné. Ce contrôle relève de l'hébergement.
- **Aucune dépendance au socle de thème.** `theme-core` et ce paquet ne se connaissent
  pas ; ils partagent seulement l'autoloader de Composer.

---

## Installation

```bash
composer require brumisphere/hardening
```

Le mu-plugin `00-autoload.php` décrit dans le README de `theme-core` met en place
l'autoloader. Déposer ensuite `mu-plugin/10-brumisphere-hardening.php` dans
`wp-content/mu-plugins/`.

Le préfixe `10-` n'est pas décoratif : WordPress charge les mu-plugins dans l'ordre
alphabétique des noms de fichiers, et l'autoloader doit être en place avant l'amorce.

> **Le répertoire `vendor/` doit être inaccessible depuis le navigateur.** Sur un
> WordPress classique il se trouve sous la racine web. La règle `.htaccess` et le
> contrôle associé figurent dans le README de `theme-core` ; ils valent aussi pour ce
> paquet.

---

## Configuration

Tous les modules sont actifs par défaut. La recette de sécurité d'un site livré exige
ces contrôles : un durcissement qu'il faut penser à allumer n'est pas allumé.

| Interrupteur | Défaut | Effet |
|---|---|---|
| `entetes` | `true` | Envoi des en-têtes de sécurité |
| `entetes_hsts` | `true` | Ajoute HSTS, uniquement si la réponse est en HTTPS |
| `divulgation` | `true` | Masque la version, les liens de découverte, le motif d'échec de connexion |
| `xmlrpc` | `true` | Coupe XML-RPC et répond 403 sur `xmlrpc.php` |
| `enumeration` | `true` | Archives d'auteur en 404, `/wp/v2/users` retiré aux anonymes |
| `edition_fichiers` | `true` | Retire l'éditeur de code de l'administration |
| `televersement` | `true` | Refuse les extensions exécutables, retire le SVG |

Un site désactive un module depuis son propre mu-plugin :

```php
<?php
// wp-content/mu-plugins/20-monsite.php
declare(strict_types=1);

add_filter(
	'brumisphere/hardening/options',
	static function ( array $options ): array {
		// Ce site publie des pages d'auteur.
		$options['enumeration'] = false;

		return $options;
	}
);
```

Le filtre est résolu au premier besoin, pas à l'amorce : un mu-plugin chargé après
celui-ci peut donc encore agir. Les clés inconnues sont ignorées, et une option orpheline
laissée dans un site après le retrait d'un module ne réactive rien.

Les en-têtes eux-mêmes se filtrent par `brumisphere/hardening/entetes`.

---

## Conséquences à connaître

Trois modules sont visibles de l'extérieur. Ils sont désactivables un par un, mais il
vaut mieux les connaître avant la mise en service que les découvrir en recette.

**`enumeration` renvoie 404 sur toutes les archives d'auteur**, flux compris. Un site
qui publie réellement des pages d'auteur doit désactiver le module, pas le contourner.

**`televersement` refuse le SVG.** Un SVG est un document XML qui peut contenir du
script, exécuté dans le contexte du domaine. Un site qui en a besoin installe d'abord un
assainisseur, puis désactive le module.

**`entetes` pose `X-Frame-Options: SAMEORIGIN`.** Si un partenaire affiche légitimement
le site dans un cadre depuis un autre domaine, l'en-tête doit être ajusté par le filtre.

**`DISALLOW_FILE_MODS` n'est volontairement pas posé.** Cette constante couperait les
mises à jour depuis l'administration, donc celles de Flatsome et d'ACF Pro, dont le
système de mise à jour repose sur un code d'achat enregistré en base de données (DEC-002).
Le durcissement casserait la chaîne de mise à jour des deux produits sous licence du parc.
Seul l'éditeur de code est retiré, par le filtre `file_mod_allowed`, ce qui n'entre pas en
conflit avec un `wp-config.php` qui aurait déjà posé la constante.

---

## Vérification

```bash
composer install    # une fois : installe les outils de test
composer test       # 37 cas, sans installation de WordPress
composer lint       # PHPCS, conventions WordPress
composer analyse    # PHPStan niveau 6
```

Les tests unitaires doublent les quelques fonctions WordPress appelées par les modules et
vérifient deux choses : que chaque module branche bien ce qu'il annonce, et que chaque
fonction de rappel répond correctement à des entrées hostiles — noms de fichiers à double
extension, octet nul, chemins relatifs, casse inversée sur `xmlrpc.php`, clés MIME
groupées.

Les contrôles d'intégration se jouent contre un site réel :

```bash
./tests/integration.sh https://mon-site.ddev.site
```

**À rejouer après bascule du site sur un thème par défaut.** Les résultats doivent être
identiques : c'est ce qui prouve que le durcissement est au bon endroit.

---

## Correspondance avec la recette de sécurité

| Contrôle de la recette | Couvert par |
|---|---|
| Version de WordPress exposée | `Divulgation` |
| Énumération d'utilisateurs | `Enumeration` |
| `wp/xmlrpc.php` en 403 | `Divulgation` |
| En-têtes de sécurité | `Entetes` |
| Upload : SVG interdit ou assaini | `Televersement` |
| Comptes, mots de passe, double authentification | **hors périmètre**, geste d'exploitation |
| Extensions inutilisées désinstallées | **hors périmètre**, geste d'exploitation |
| `debug.log` et `WP_DEBUG_DISPLAY` | **hors périmètre**, relève de `wp-config.php` |
| Préproduction non indexable et protégée | **hors périmètre**, relève de l'hébergement |

---

## Versionnement

Versionnement sémantique. Les sites contraignent en `^1.0`.

| Changement | Incrément |
|---|---|
| Correction sans effet observable | Correctif |
| Nouveau module, nouvel interrupteur | Mineur |
| Module actif par défaut qui ne l'était pas | **Majeur** |
| Retrait ou renommage d'un interrupteur | **Majeur** |
| Changement de signature d'une méthode publique | **Majeur** |

Rendre un contrôle plus strict par défaut est une rupture : un site du parc peut en
dépendre sans le savoir. `CHANGELOG.md` est obligatoire dès le premier tag.
