<?php
/**
 * Restriction des fichiers téléversés.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Hardening;
use Brumisphere\Hardening\Televersement;

bru_cas(
	'les noms hostiles sont refusés, les noms légitimes acceptés',
	static function (): void {
		$entrees = array(
			// Refusés.
			'shell.php'                  => true,
			'photo.php.jpg'              => true,
			'photo.jpg.php'              => true,
			'photo.PHP.jpg'              => true,
			'shell.phtml'                => true,
			'shell.phar'                 => true,
			'shell.php5'                 => true,
			'shell.php '                 => true,
			'shell.php.'                 => true,
			'../../shell.php'            => true,
			'..\\..\\shell.php'          => true,
			'.htaccess'                  => true,
			"photo\0.php"                => true,
			"photo.php\0.jpg"            => true,
			// Acceptés.
			'photo.jpg'                  => false,
			'archive.tar.gz'             => false,
			'rapport.2026.final.pdf'     => false,
			'photographie.png'           => false,
			'note-de-cadrage.docx'       => false,
			'telephone.mp4'              => false,
		);

		foreach ( $entrees as $nom => $attendu ) {
			bru_egal(
				$attendu,
				Televersement::nom_dangereux( (string) $nom ),
				'verdict pour ' . var_export( $nom, true )
			);
		}
	}
);

bru_cas(
	'un fichier dangereux est refusé par le pré-filtre',
	static function (): void {
		Hardening::boot();

		$resultat = Televersement::refuser_fichier_dangereux(
			array(
				'name' => 'photo.php.jpg',
				'type' => 'image/jpeg',
			)
		);

		bru_vrai( isset( $resultat['error'] ), 'une erreur est posée sur le fichier' );
	}
);

bru_cas(
	'un fichier légitime passe sans erreur',
	static function (): void {
		Hardening::boot();

		$resultat = Televersement::refuser_fichier_dangereux(
			array(
				'name' => 'photo.jpg',
				'type' => 'image/jpeg',
			)
		);

		bru_faux( isset( $resultat['error'] ), 'aucune erreur n’est posée' );
	}
);

bru_cas(
	'le SVG est retiré des types acceptés',
	static function (): void {
		Hardening::boot();

		$types = Televersement::retirer_svg(
			array(
				'jpg|jpeg|jpe' => 'image/jpeg',
				'png'          => 'image/png',
				'svg'          => 'image/svg+xml',
				'svgz'         => 'image/svg+xml',
				'pdf'          => 'application/pdf',
			)
		);

		bru_faux( isset( $types['svg'] ), 'svg est retiré' );
		bru_faux( isset( $types['svgz'] ), 'svgz est retiré' );
		bru_vrai( isset( $types['png'] ), 'png est conservé' );
		bru_vrai( isset( $types['jpg|jpeg|jpe'] ), 'les images restent acceptées' );
	}
);

bru_cas(
	'une clé groupée contenant svg est retirée entièrement',
	static function (): void {
		Hardening::boot();

		// Certaines extensions déclarent "svg|svgz" en une seule clé : retirer la clé
		// exacte "svg" ne suffirait pas.
		$types = Televersement::retirer_svg(
			array(
				'svg|svgz' => 'image/svg+xml',
				'webp'     => 'image/webp',
			)
		);

		bru_faux( isset( $types['svg|svgz'] ), 'la clé groupée est retirée' );
		bru_vrai( isset( $types['webp'] ), 'les autres types sont conservés' );
	}
);

bru_cas(
	'module désactivé, les types sont intacts',
	static function (): void {
		Hardening::boot( array( 'televersement' => false ) );

		$types = array( 'svg' => 'image/svg+xml' );

		bru_egal( $types, Televersement::retirer_svg( $types ), 'rien n’est retiré' );

		$fichier = array( 'name' => 'shell.php' );

		bru_faux( isset( Televersement::refuser_fichier_dangereux( $fichier )['error'] ), 'aucune erreur n’est posée' );
	}
);

bru_cas(
	'svg_restreint est déclaré, éteint par défaut',
	static function (): void {
		Hardening::boot();

		$defauts = Hardening::defauts();

		bru_vrai( array_key_exists( 'svg_restreint', $defauts ), 'l’interrupteur est déclaré' );
		bru_faux( $defauts['svg_restreint'] ?? true, 'il est éteint par défaut' );
		bru_faux( Hardening::actif( 'svg_restreint' ), 'il est inactif sans surcharge' );
	}
);

/**
 * Types acceptés tels qu'une extension permissive les laisse : le SVG ouvert à tous.
 *
 * @return array<string, string>
 */
function bru_types_avec_svg(): array {
	return array(
		'jpg|jpeg|jpe' => 'image/jpeg',
		'png'          => 'image/png',
		'svg'          => 'image/svg+xml',
		'svg|svgz'     => 'image/svg+xml',
	);
}

bru_cas(
	'svg_restreint allumé, un compte sans unfiltered_html perd le SVG',
	static function (): void {
		Hardening::boot( array( 'svg_restreint' => true ) );

		$types = Televersement::restreindre_svg( bru_types_avec_svg() );

		bru_faux( isset( $types['svg'] ), 'svg est retiré' );
		bru_faux( isset( $types['svg|svgz'] ), 'la clé groupée est retirée' );
		bru_vrai( isset( $types['png'], $types['jpg|jpeg|jpe'] ), 'les images restent acceptées' );
	}
);

bru_cas(
	'svg_restreint allumé, un compte unfiltered_html garde le SVG',
	static function (): void {
		Hardening::boot( array( 'svg_restreint' => true ) );
		$GLOBALS['bru']['capacites'] = array( 'unfiltered_html' );

		bru_egal( bru_types_avec_svg(), Televersement::restreindre_svg( bru_types_avec_svg() ), 'rien n’est retiré' );
	}
);

bru_cas(
	'l’utilisateur passé par WordPress prime sur l’utilisateur courant',
	static function (): void {
		Hardening::boot( array( 'svg_restreint' => true ) );

		// Même règle que get_allowed_mime_types() : user_can( $user ) si un utilisateur
		// est passé, current_user_can() sinon.
		$GLOBALS['bru']['capacites']       = array( 'unfiltered_html' );
		$GLOBALS['bru']['capacites_de'][7] = array();

		bru_faux( isset( Televersement::restreindre_svg( bru_types_avec_svg(), 7 )['svg'] ), 'compte 7 sans unfiltered_html : svg retiré' );

		$GLOBALS['bru']['capacites']       = array();
		$GLOBALS['bru']['capacites_de'][8] = array( 'unfiltered_html' );

		bru_vrai( isset( Televersement::restreindre_svg( bru_types_avec_svg(), 8 )['svg'] ), 'compte 8 avec unfiltered_html : svg conservé' );
	}
);

bru_cas(
	'svg_restreint éteint, les types sont intacts',
	static function (): void {
		Hardening::boot();

		bru_egal( bru_types_avec_svg(), Televersement::restreindre_svg( bru_types_avec_svg() ), 'rien n’est retiré' );
	}
);

bru_cas(
	'svg_restreint ne dépend pas de televersement',
	static function (): void {
		Hardening::boot(
			array(
				'televersement' => false,
				'svg_restreint' => true,
			)
		);

		bru_faux( isset( Televersement::restreindre_svg( bru_types_avec_svg() )['svg'] ), 'svg retiré, televersement éteint' );
	}
);

bru_cas(
	'svg_restreint est branché après les thèmes et les extensions',
	static function (): void {
		Hardening::boot();

		$trouve = null;

		foreach ( $GLOBALS['bru']['filtres']['upload_mimes'] ?? array() as $entree ) {
			if ( array( Televersement::class, 'restreindre_svg' ) === $entree[0] ) {
				$trouve = $entree;
			}
		}

		bru_vrai( null !== $trouve, 'restreindre_svg est branché sur upload_mimes' );
		bru_egal( PHP_INT_MAX, $trouve[1] ?? null, 'à la priorité PHP_INT_MAX' );
		bru_egal( 2, $trouve[2] ?? null, 'avec l’utilisateur en second argument' );
	}
);
