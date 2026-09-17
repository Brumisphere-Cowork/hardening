<?php
/**
 * Mises à jour du cœur WordPress.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Coupe les mises à jour du cœur, qui appartiennent à Composer.
 *
 * Le cœur est installé par Composer dans wp/ et livré par la chaîne de déploiement. Une
 * mise à jour faite par WordPress lui-même sur le serveur serait écrasée au déploiement
 * suivant, ou ferait tourner en production une version jamais vue en préproduction.
 * L'annonce « WordPress x.y est disponible » invite à ce geste : elle est retirée aussi.
 *
 * Les extensions et les thèmes ne sont pas concernés : Flatsome et ACF Pro se mettent à
 * jour depuis l'administration (voir Fichiers). La veille des versions du cœur se fait
 * côté dépôt, par Composer.
 */
final class Coeur {

	/**
	 * Filtres dont la valeur devient false : mises à jour automatiques du cœur, et e-mail
	 * annonçant une nouvelle version.
	 */
	public const FILTRES_REFUSES = array(
		'auto_update_core',
		'allow_dev_auto_core_updates',
		'allow_minor_auto_core_updates',
		'allow_major_auto_core_updates',
		'send_core_update_notification_email',
	);

	/**
	 * Branche le module.
	 */
	public static function enregistrer(): void {
		foreach ( self::FILTRES_REFUSES as $filtre ) {
			add_filter( $filtre, array( self::class, 'refuser' ) );
		}

		add_filter( 'pre_site_transient_update_core', array( self::class, 'masquer_disponibilite' ) );
	}

	/**
	 * Refuse la mise à jour ou l'e-mail.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param mixed $valeur Décision courante.
	 * @return mixed
	 */
	public static function refuser( $valeur ) {
		return Hardening::actif( 'maj_coeur' ) ? false : $valeur;
	}

	/**
	 * Répond à la place de l'API : aucune nouvelle version, vérification à jour.
	 *
	 * La date du jour et la version installée dispensent WordPress d'interroger l'API ;
	 * la liste vide retire l'annonce de l'administration.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param mixed $valeur Valeur courante (false : pas de court-circuit).
	 * @return mixed
	 */
	public static function masquer_disponibilite( $valeur ) {
		if ( ! Hardening::actif( 'maj_coeur' ) ) {
			return $valeur;
		}

		return (object) array(
			'last_checked'    => time(),
			'version_checked' => (string) ( $GLOBALS['wp_version'] ?? '' ),
			'updates'         => array(),
			'translations'    => array(),
		);
	}
}
