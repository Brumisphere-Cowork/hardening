<?php
/**
 * En-têtes de sécurité HTTP.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Ajoute les en-têtes de sécurité aux réponses du site public.
 *
 * Ces en-têtes ne réparent rien : ils réduisent la portée d'une faille existante. Le
 * navigateur refuse de deviner le type d'un fichier, n'envoie pas l'URL complète en
 * référent vers un autre domaine, et n'autorise pas l'affichage du site dans un cadre
 * d'un autre domaine.
 *
 * Deux choix assumés. X-Frame-Options est posé à SAMEORIGIN plutôt qu'à DENY, car
 * l'aperçu de l'outil de personnalisation charge le site dans un cadre de même origine.
 * Strict-Transport-Security est envoyé sans includeSubDomains ni preload : ces deux
 * options engagent des sous-domaines et une liste publique dont on ne sort pas
 * rapidement, ce qui n'est pas un choix à faire à l'insu de l'exploitant.
 */
final class Entetes {

	/**
	 * Durée de vie de l'en-tête HSTS, en secondes : un an.
	 */
	private const DUREE_HSTS = 31536000;

	/**
	 * Branche le module.
	 */
	public static function enregistrer(): void {
		add_action( 'send_headers', array( self::class, 'envoyer' ) );
	}

	/**
	 * Envoie les en-têtes.
	 *
	 * Public car branché sur un hook ; ne pas appeler directement.
	 */
	public static function envoyer(): void {
		if ( ! Hardening::actif( 'entetes' ) || headers_sent() ) {
			return;
		}

		foreach ( self::liste() as $nom => $valeur ) {
			header( $nom . ': ' . $valeur, true );
		}
	}

	/**
	 * Construit la liste des en-têtes à envoyer.
	 *
	 * @return array<string, string>
	 */
	public static function liste(): array {
		$entetes = array(
			'X-Content-Type-Options' => 'nosniff',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			'X-Frame-Options'        => 'SAMEORIGIN',
			'Permissions-Policy'     => 'geolocation=(), microphone=(), camera=()',
		);

		// Envoyer HSTS sur une réponse en clair n'a aucun effet et fige une promesse
		// que le site ne tient pas encore.
		if ( Hardening::actif( 'entetes_hsts' ) && is_ssl() ) {
			$entetes['Strict-Transport-Security'] = 'max-age=' . self::DUREE_HSTS;
		}

		/**
		 * Filtre les en-têtes de sécurité avant envoi.
		 *
		 * @param array<string, string> $entetes Couples nom / valeur.
		 */
		$filtres = apply_filters( 'brumisphere/hardening/entetes', $entetes );

		return is_array( $filtres ) ? $filtres : $entetes;
	}
}
