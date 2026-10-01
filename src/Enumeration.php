<?php
/**
 * Blocage de l'énumération des comptes.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Empêche un visiteur anonyme d'obtenir la liste des identifiants du site.
 *
 * WordPress expose les comptes par deux chemins. L'archive d'auteur redirige /?author=1
 * vers /author/<identifiant>/, ce qui révèle l'identifiant de connexion du compte
 * numéro un, presque toujours un administrateur. L'API REST /wp/v2/users renvoie la
 * même information en JSON, sans authentification, depuis WordPress 4.7.
 *
 * Connaître l'identifiant ne donne aucun accès, mais divise par deux le travail d'une
 * attaque par force brute : il ne reste qu'à trouver le mot de passe.
 *
 * Conséquence à connaître. Les archives d'auteur renvoient 404, y compris leurs flux.
 * Un site de presse qui publie des pages d'auteur doit désactiver ce module plutôt que
 * de le contourner.
 */
final class Enumeration {

	/**
	 * Points de terminaison REST retirés aux visiteurs anonymes.
	 */
	private const POINTS_UTILISATEURS = array(
		'/wp/v2/users',
		'/wp/v2/users/(?P<id>[\d]+)',
	);

	/**
	 * Priorité du blocage d'archive sur template_redirect.
	 *
	 * Le cœur branche redirect_canonical sur la même accroche, en 10, depuis
	 * default-filters.php, chargé avant les mu-plugins. À priorité égale, le premier
	 * enregistré passe : jusqu'en 1.0.20, /?author=1 partait en 301 vers l'archive
	 * nommée, suivie d'un exit, et le 404 n'arrivait jamais.
	 */
	private const PRIORITE_BLOCAGE = 1;

	/**
	 * Branche le module.
	 */
	public static function enregistrer(): void {
		add_action( 'template_redirect', array( self::class, 'bloquer_archive_auteur' ), self::PRIORITE_BLOCAGE );
		add_filter( 'redirect_canonical', array( self::class, 'refuser_redirection_auteur' ) );
		add_filter( 'rest_endpoints', array( self::class, 'retirer_points_utilisateurs' ) );
	}

	/**
	 * Transforme une archive d'auteur en 404.
	 *
	 * Public car branché sur un hook ; ne pas appeler directement.
	 */
	public static function bloquer_archive_auteur(): void {
		if ( ! Hardening::actif( 'enumeration' ) || ! is_author() ) {
			return;
		}

		global $wp_query;

		if ( $wp_query instanceof \WP_Query ) {
			$wp_query->set_404();
		}

		status_header( 404 );
		nocache_headers();
	}

	/**
	 * Refuse la redirection canonique d'une requête d'auteur.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * Le blocage d'archive passe avant redirect_canonical, mais set_404() remet
	 * is_author() à faux : redirect_canonical passe alors par sa branche 404 et peut
	 * encore normaliser l'adresse. Les variables de requête survivent à set_404() ;
	 * c'est sur elles que porte le refus.
	 *
	 * @param mixed $redirection Adresse proposée par WordPress, ou false.
	 * @return mixed False pour une requête d'auteur, sinon la valeur reçue.
	 */
	public static function refuser_redirection_auteur( $redirection ) {
		if ( ! Hardening::actif( 'enumeration' ) || ! self::requete_auteur() ) {
			return $redirection;
		}

		return false;
	}

	/**
	 * Indique si la requête vise une archive d'auteur, par numéro ou par nom.
	 */
	private static function requete_auteur(): bool {
		return ! empty( get_query_var( 'author' ) ) || ! empty( get_query_var( 'author_name' ) );
	}

	/**
	 * Retire les points de terminaison des utilisateurs aux visiteurs anonymes.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * Le retrait ne vise que les requêtes non authentifiées : l'éditeur de WordPress a
	 * besoin de ces points pour fonctionner, et le supprimer pour tout le monde casse
	 * l'administration.
	 *
	 * @param array<string, mixed> $points Points de terminaison déclarés.
	 * @return array<string, mixed>
	 */
	public static function retirer_points_utilisateurs( array $points ): array {
		if ( ! Hardening::actif( 'enumeration' ) || is_user_logged_in() ) {
			return $points;
		}

		foreach ( self::POINTS_UTILISATEURS as $chemin ) {
			unset( $points[ $chemin ] );
		}

		return $points;
	}
}
