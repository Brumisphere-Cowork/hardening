<?php
/**
 * Éditeur de fichiers de l'administration.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Fichiers;
use Brumisphere\Hardening\Hardening;

bru_cas(
	'l’éditeur de thèmes et d’extensions est refusé',
	static function (): void {
		Hardening::boot();

		bru_faux( Fichiers::interdire_edition( true, 'capability_edit_themes' ), 'l’édition est refusée' );
	}
);

bru_cas(
	'les mises à jour restent possibles',
	static function (): void {
		Hardening::boot();

		// C'est la contrepartie de DISALLOW_FILE_MODS, écartée volontairement : Flatsome
		// et ACF Pro se mettent à jour depuis l'administration, avec un code d'achat
		// enregistré en base de données.
		$contextes = array(
			'capability_update_core',
			'capability_install_themes',
			'capability_install_plugins',
			'automatic_updater',
			'',
		);

		foreach ( $contextes as $contexte ) {
			bru_vrai(
				Fichiers::interdire_edition( true, $contexte ),
				'le contexte ' . var_export( $contexte, true ) . ' reste autorisé'
			);
		}
	}
);

bru_cas(
	'une interdiction déjà posée ailleurs est respectée',
	static function (): void {
		Hardening::boot();

		// wp-config.php a pu poser DISALLOW_FILE_MODS : le module ne doit pas
		// réautoriser ce qu'une autre décision a interdit.
		bru_faux( Fichiers::interdire_edition( false, 'capability_update_core' ), 'la décision antérieure est conservée' );
	}
);

bru_cas(
	'module désactivé, la décision est transmise',
	static function (): void {
		Hardening::boot( array( 'edition_fichiers' => false ) );

		bru_vrai( Fichiers::interdire_edition( true, 'capability_edit_themes' ), 'l’interrupteur est respecté' );
	}
);
