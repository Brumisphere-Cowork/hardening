<?php
/**
 * Mises à jour du cœur WordPress.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Coeur;
use Brumisphere\Hardening\Hardening;

bru_cas(
	'les filtres du cœur sont branchés',
	static function (): void {
		Hardening::boot();

		foreach ( array_merge( Coeur::FILTRES_REFUSES, array( 'pre_site_transient_update_core' ) ) as $filtre ) {
			bru_vrai( ! empty( $GLOBALS['bru']['filtres'][ $filtre ] ), 'filtre ' . $filtre . ' branché' );
		}
	}
);

bru_cas(
	'les mises à jour automatiques du cœur et l’e-mail sont refusés',
	static function (): void {
		Hardening::boot();

		bru_faux( Coeur::refuser( true ), 'la mise à jour est refusée' );
	}
);

bru_cas(
	'aucune nouvelle version n’est annoncée',
	static function (): void {
		Hardening::boot();
		$GLOBALS['wp_version'] = '7.1';

		$reponse = Coeur::masquer_disponibilite( false );

		bru_vrai( is_object( $reponse ), 'la réponse de l’API est remplacée' );
		bru_vrai( array() === $reponse->updates, 'aucune mise à jour proposée' );
		bru_vrai( '7.1' === $reponse->version_checked, 'la version installée est déclarée vérifiée' );
		bru_vrai( $reponse->last_checked >= time() - 5, 'la vérification est datée du jour' );
	}
);

bru_cas(
	'les extensions et les thèmes ne sont pas touchés',
	static function (): void {
		Hardening::boot();

		foreach ( array( 'auto_update_plugin', 'auto_update_theme', 'pre_site_transient_update_plugins', 'pre_site_transient_update_themes' ) as $filtre ) {
			bru_vrai( empty( $GLOBALS['bru']['filtres'][ $filtre ] ), 'filtre ' . $filtre . ' laissé libre' );
		}
	}
);

bru_cas(
	'module désactivé, les décisions sont transmises',
	static function (): void {
		Hardening::boot( array( 'maj_coeur' => false ) );

		bru_vrai( Coeur::refuser( true ), 'la mise à jour reste décidée par WordPress' );
		bru_faux( Coeur::masquer_disponibilite( false ), 'l’API est interrogée normalement' );
	}
);
