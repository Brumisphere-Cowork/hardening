<?php
/**
 * Blocage de l'énumération des comptes.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Enumeration;
use Brumisphere\Hardening\Hardening;

/**
 * Jeu de points de terminaison représentatif d'un site réel.
 *
 * @return array<string, mixed>
 */
function bru_points_rest(): array {
	return array(
		'/wp/v2/users'                 => 'rappel',
		'/wp/v2/users/(?P<id>[\d]+)'   => 'rappel',
		'/wp/v2/posts'                 => 'rappel',
		'/wp/v2/media'                 => 'rappel',
	);
}

bru_cas(
	'un visiteur anonyme n’obtient pas la liste des comptes',
	static function (): void {
		Hardening::boot();

		$points = Enumeration::retirer_points_utilisateurs( bru_points_rest() );

		bru_faux( isset( $points['/wp/v2/users'] ), 'la collection des utilisateurs est retirée' );
		bru_faux( isset( $points['/wp/v2/users/(?P<id>[\d]+)'] ), 'la fiche d’un utilisateur est retirée' );
		bru_vrai( isset( $points['/wp/v2/posts'] ), 'les autres points restent accessibles' );
		bru_vrai( isset( $points['/wp/v2/media'] ), 'la médiathèque reste accessible' );
	}
);

bru_cas(
	'un utilisateur connecté garde l’API complète',
	static function (): void {
		$GLOBALS['bru']['is_user_logged_in'] = true;
		Hardening::boot();

		$points = Enumeration::retirer_points_utilisateurs( bru_points_rest() );

		bru_vrai( isset( $points['/wp/v2/users'] ), 'l’éditeur de WordPress continue de fonctionner' );
	}
);

bru_cas(
	'module désactivé, l’API est intacte',
	static function (): void {
		Hardening::boot( array( 'enumeration' => false ) );

		bru_egal( bru_points_rest(), Enumeration::retirer_points_utilisateurs( bru_points_rest() ), 'rien n’est retiré' );
	}
);

bru_cas(
	'une archive d’auteur renvoie 404',
	static function (): void {
		$GLOBALS['bru']['is_author'] = true;
		Hardening::boot();

		$requete            = new WP_Query();
		$GLOBALS['wp_query'] = $requete;

		Enumeration::bloquer_archive_auteur();

		bru_egal( 404, $GLOBALS['bru']['statut'], 'le code de statut est 404' );
		bru_vrai( $requete->est_404, 'la requête est marquée introuvable' );
	}
);

bru_cas(
	'une page ordinaire n’est pas touchée',
	static function (): void {
		$GLOBALS['bru']['is_author'] = false;
		Hardening::boot();

		$requete            = new WP_Query();
		$GLOBALS['wp_query'] = $requete;

		Enumeration::bloquer_archive_auteur();

		bru_egal( 0, $GLOBALS['bru']['statut'], 'aucun statut n’est forcé' );
		bru_faux( $requete->est_404, 'la requête reste intacte' );
	}
);

/**
 * Priorité du blocage d'archive d'auteur sur template_redirect.
 *
 * @return int|null Null si le blocage n'est pas branché.
 */
function bru_priorite_blocage_auteur(): ?int {
	foreach ( $GLOBALS['bru']['actions']['template_redirect'] ?? array() as $entree ) {
		if ( array( Enumeration::class, 'bloquer_archive_auteur' ) === $entree[0] ) {
			return $entree[1];
		}
	}

	return null;
}

bru_cas(
	'le blocage d’archive d’auteur passe avant redirect_canonical',
	static function (): void {
		Hardening::boot();

		$priorite = bru_priorite_blocage_auteur();

		bru_vrai( null !== $priorite, 'le blocage est branché sur template_redirect' );
		bru_vrai(
			10 > $priorite,
			'le cœur branche redirect_canonical en 10 avant les mu-plugins : à égalité, la redirection part avant le 404 — priorité obtenue ' . var_export( $priorite, true )
		);
	}
);

bru_cas(
	'/?author=1 ne redirige plus vers l’identifiant',
	static function (): void {
		Hardening::boot();
		$GLOBALS['bru']['requete']['author'] = '1';

		bru_vrai(
			bru_branche( 'filtres', 'redirect_canonical', Enumeration::class, 'refuser_redirection_auteur' ),
			'le refus est branché sur redirect_canonical'
		);
		bru_egal(
			false,
			apply_filters( 'redirect_canonical', 'http://exemple.test/author/admin/', 'http://exemple.test/?author=1' ),
			'la redirection canonique est refusée'
		);
	}
);

bru_cas(
	'une archive d’auteur par son nom ne redirige pas non plus',
	static function (): void {
		Hardening::boot();
		$GLOBALS['bru']['requete']['author_name'] = 'admin';

		bru_egal(
			false,
			apply_filters( 'redirect_canonical', 'http://exemple.test/author/admin/', 'http://exemple.test/author/admin' ),
			'la redirection canonique est refusée'
		);
	}
);

bru_cas(
	'une requête ordinaire garde sa redirection canonique',
	static function (): void {
		Hardening::boot();

		bru_egal(
			'http://exemple.test/contact/',
			apply_filters( 'redirect_canonical', 'http://exemple.test/contact/', 'http://exemple.test/contact' ),
			'la redirection est rendue intacte'
		);
	}
);

bru_cas(
	'module désactivé, /?author=1 garde sa redirection',
	static function (): void {
		Hardening::boot( array( 'enumeration' => false ) );
		$GLOBALS['bru']['requete']['author'] = '1';

		bru_egal(
			'http://exemple.test/author/admin/',
			apply_filters( 'redirect_canonical', 'http://exemple.test/author/admin/', 'http://exemple.test/?author=1' ),
			'rien n’est refusé'
		);
	}
);
