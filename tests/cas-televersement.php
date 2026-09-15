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
