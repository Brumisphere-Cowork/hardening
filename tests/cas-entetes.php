<?php
/**
 * En-têtes de sécurité.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Entetes;
use Brumisphere\Hardening\Hardening;

bru_cas(
	'les quatre en-têtes de base sont présents',
	static function (): void {
		Hardening::boot();

		$entetes = Entetes::liste();

		bru_egal( 'nosniff', $entetes['X-Content-Type-Options'] ?? null, 'nosniff est posé' );
		bru_egal( 'strict-origin-when-cross-origin', $entetes['Referrer-Policy'] ?? null, 'la politique de référent est posée' );
		bru_egal( 'SAMEORIGIN', $entetes['X-Frame-Options'] ?? null, 'le cadrage est limité à la même origine' );
		bru_vrai( isset( $entetes['Permissions-Policy'] ), 'la politique de permissions est posée' );
	}
);

bru_cas(
	'HSTS est absent en clair',
	static function (): void {
		$GLOBALS['bru']['is_ssl'] = false;
		Hardening::boot();

		bru_faux(
			isset( Entetes::liste()['Strict-Transport-Security'] ),
			'aucune promesse HTTPS sur une réponse en clair'
		);
	}
);

bru_cas(
	'HSTS est présent en HTTPS',
	static function (): void {
		$GLOBALS['bru']['is_ssl'] = true;
		Hardening::boot();

		bru_egal(
			'max-age=31536000',
			Entetes::liste()['Strict-Transport-Security'] ?? null,
			'HSTS est posé pour un an, sans includeSubDomains ni preload'
		);
	}
);

bru_cas(
	'HSTS peut être désactivé seul',
	static function (): void {
		$GLOBALS['bru']['is_ssl'] = true;
		Hardening::boot( array( 'entetes_hsts' => false ) );

		$entetes = Entetes::liste();

		bru_faux( isset( $entetes['Strict-Transport-Security'] ), 'HSTS est retiré' );
		bru_vrai( isset( $entetes['X-Content-Type-Options'] ), 'les autres en-têtes restent' );
	}
);

bru_cas(
	'les en-têtes sont réellement émis',
	static function (): void {
		Hardening::boot();
		Entetes::envoyer();

		bru_vrai(
			in_array( 'X-Content-Type-Options: nosniff', $GLOBALS['bru']['entetes_envoyes'], true ),
			'l’en-tête part sur la réponse'
		);
	}
);

bru_cas(
	'rien n’est émis si les en-têtes sont déjà partis',
	static function (): void {
		$GLOBALS['bru']['headers_sent'] = true;
		Hardening::boot();
		Entetes::envoyer();

		bru_egal( array(), $GLOBALS['bru']['entetes_envoyes'], 'aucun avertissement PHP provoqué' );
	}
);

bru_cas(
	'module désactivé, rien n’est émis',
	static function (): void {
		Hardening::boot( array( 'entetes' => false ) );
		Entetes::envoyer();

		bru_egal( array(), $GLOBALS['bru']['entetes_envoyes'], 'l’interrupteur est respecté' );
	}
);
