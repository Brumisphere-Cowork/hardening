<?php
/**
 * Amorce, résolution des options et branchement des accroches.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Divulgation;
use Brumisphere\Hardening\Entetes;
use Brumisphere\Hardening\Enumeration;
use Brumisphere\Hardening\Fichiers;
use Brumisphere\Hardening\Hardening;
use Brumisphere\Hardening\Televersement;

bru_cas(
	'tous les interrupteurs sont actifs par défaut',
	static function (): void {
		Hardening::boot();

		foreach ( array_keys( Hardening::defauts() ) as $cle ) {
			bru_vrai( Hardening::actif( $cle ), 'interrupteur actif par défaut : ' . $cle );
		}
	}
);

bru_cas(
	'une clé inconnue est inactive',
	static function (): void {
		Hardening::boot();

		bru_faux( Hardening::actif( 'module_inexistant' ), 'une option orpheline ne réactive rien' );
	}
);

bru_cas(
	'une surcharge du site désactive un module',
	static function (): void {
		Hardening::boot( array( 'enumeration' => false ) );

		bru_faux( Hardening::actif( 'enumeration' ), 'la surcharge est appliquée' );
		bru_vrai( Hardening::actif( 'entetes' ), 'les autres modules restent actifs' );
	}
);

bru_cas(
	'une surcharge inconnue est ignorée',
	static function (): void {
		Hardening::boot( array( 'inconnu' => true ) );

		bru_faux( Hardening::actif( 'inconnu' ), 'aucune option n’est créée par surcharge' );
	}
);

bru_cas(
	'le filtre est appliqué après les surcharges',
	static function (): void {
		Hardening::boot( array( 'entetes' => false ) );

		add_filter(
			'brumisphere/hardening/options',
			static function ( array $options ): array {
				$options['entetes'] = true;

				return $options;
			}
		);

		bru_vrai( Hardening::actif( 'entetes' ), 'le filtre prime sur la surcharge' );
	}
);

bru_cas(
	'une seconde amorce est sans effet',
	static function (): void {
		Hardening::boot( array( 'xmlrpc' => false ) );
		Hardening::boot( array( 'xmlrpc' => true ) );

		bru_faux( Hardening::actif( 'xmlrpc' ), 'la première amorce fait foi' );
	}
);

bru_cas(
	'chaque module branche ses accroches',
	static function (): void {
		Hardening::boot();

		$attendus = array(
			array( 'actions', 'send_headers', Entetes::class, 'envoyer' ),
			array( 'actions', 'muplugins_loaded', Divulgation::class, 'couper_xmlrpc' ),
			array( 'actions', 'init', Divulgation::class, 'nettoyer_entete' ),
			array( 'filtres', 'the_generator', Divulgation::class, 'masquer_generateur' ),
			array( 'filtres', 'wp_headers', Divulgation::class, 'retirer_pingback' ),
			array( 'filtres', 'xmlrpc_enabled', Divulgation::class, 'xmlrpc_desactive' ),
			array( 'filtres', 'xmlrpc_methods', Divulgation::class, 'vider_methodes' ),
			array( 'filtres', 'login_errors', Divulgation::class, 'message_generique' ),
			array( 'actions', 'template_redirect', Enumeration::class, 'bloquer_archive_auteur' ),
			array( 'filtres', 'rest_endpoints', Enumeration::class, 'retirer_points_utilisateurs' ),
			array( 'filtres', 'file_mod_allowed', Fichiers::class, 'interdire_edition' ),
			array( 'filtres', 'upload_mimes', Televersement::class, 'retirer_svg' ),
			array( 'filtres', 'wp_handle_upload_prefilter', Televersement::class, 'refuser_fichier_dangereux' ),
		);

		foreach ( $attendus as $attendu ) {
			bru_vrai(
				bru_branche( $attendu[0], $attendu[1], $attendu[2], $attendu[3] ),
				$attendu[1] . ' est branché sur ' . $attendu[2] . '::' . $attendu[3]
			);
		}
	}
);
