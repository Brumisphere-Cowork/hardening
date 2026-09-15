<?php
/**
 * Réduction des informations divulguées par WordPress.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Retire de la réponse ce qui renseigne un attaquant sans servir un visiteur.
 *
 * La version exacte de WordPress permet de cibler une vulnérabilité connue sans avoir à
 * la chercher. Le message d'erreur de connexion natif distingue « identifiant inconnu »
 * de « mot de passe erroné », ce qui transforme le formulaire en oracle : on y valide
 * une liste d'identifiants avant même de tenter un mot de passe.
 *
 * XML-RPC est coupé à trois niveaux, du plus fin au plus radical. Les filtres suffisent
 * à rendre l'interface inerte, mais laissent xmlrpc.php répondre 200 avec une erreur,
 * ce que la recette de sécurité refuse. La requête est donc arrêtée en amont avec un
 * code 403.
 */
final class Divulgation {

	/**
	 * Message unique renvoyé quelle que soit la cause de l'échec de connexion.
	 */
	private const MESSAGE_CONNEXION = 'Identifiants incorrects.';

	/**
	 * Branche le module.
	 */
	public static function enregistrer(): void {
		add_action( 'muplugins_loaded', array( self::class, 'couper_xmlrpc' ), 0 );
		add_action( 'init', array( self::class, 'nettoyer_entete' ) );

		add_filter( 'the_generator', array( self::class, 'masquer_generateur' ) );
		add_filter( 'wp_headers', array( self::class, 'retirer_pingback' ) );
		add_filter( 'xmlrpc_enabled', array( self::class, 'xmlrpc_desactive' ) );
		add_filter( 'xmlrpc_methods', array( self::class, 'vider_methodes' ) );
		add_filter( 'login_errors', array( self::class, 'message_generique' ) );
	}

	/**
	 * Arrête une requête vers xmlrpc.php avec un code 403.
	 *
	 * Public car branché sur un hook ; ne pas appeler directement.
	 *
	 * Lit $_SERVER, jamais $_GET ni $_POST : aucune donnée soumise n'est interprétée,
	 * la seule information utilisée est le script appelé, comparé à un nom fixe.
	 */
	public static function couper_xmlrpc(): void {
		if ( ! Hardening::actif( 'xmlrpc' ) ) {
			return;
		}

		$script = isset( $_SERVER['SCRIPT_FILENAME'] )
			? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) )
			: '';

		if ( ! self::est_requete_xmlrpc( $script ) ) {
			return;
		}

		status_header( 403 );
		header( 'Content-Type: text/plain; charset=utf-8' );
		echo esc_html( 'XML-RPC est desactive sur ce site.' );
		exit;
	}

	/**
	 * Indique si le script appelé est xmlrpc.php.
	 *
	 * La comparaison est insensible à la casse : un système de fichiers qui l'ignore
	 * servirait XMLRPC.PHP par le même chemin, et le contrôle serait contourné.
	 *
	 * @param string $script Valeur de SCRIPT_FILENAME.
	 */
	public static function est_requete_xmlrpc( string $script ): bool {
		$nom = basename( str_replace( '\\', '/', $script ) );

		return 'xmlrpc.php' === strtolower( $nom );
	}

	/**
	 * Retire les liens de découverte de l'en-tête HTML.
	 *
	 * Public car branché sur un hook ; ne pas appeler directement.
	 *
	 * Selon la version de WordPress, certaines de ces actions ne sont plus déclarées.
	 * remove_action sur une action absente ne fait rien : le module reste valable sur
	 * les versions où elles existent encore.
	 */
	public static function nettoyer_entete(): void {
		if ( ! Hardening::actif( 'divulgation' ) ) {
			return;
		}

		remove_action( 'wp_head', 'wp_generator' );
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
	}

	/**
	 * Vide la balise générateur.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param string $generateur Balise produite par WordPress.
	 */
	public static function masquer_generateur( string $generateur ): string {
		return Hardening::actif( 'divulgation' ) ? '' : $generateur;
	}

	/**
	 * Retire l'en-tête X-Pingback.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param array<string, string> $entetes En-têtes de la réponse.
	 * @return array<string, string>
	 */
	public static function retirer_pingback( array $entetes ): array {
		if ( ! Hardening::actif( 'divulgation' ) ) {
			return $entetes;
		}

		unset( $entetes['X-Pingback'] );

		return $entetes;
	}

	/**
	 * Déclare XML-RPC désactivé.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param bool $actif État transmis par WordPress.
	 */
	public static function xmlrpc_desactive( bool $actif ): bool {
		return Hardening::actif( 'xmlrpc' ) ? false : $actif;
	}

	/**
	 * Retire toutes les méthodes XML-RPC.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param array<string, mixed> $methodes Méthodes déclarées.
	 * @return array<string, mixed>
	 */
	public static function vider_methodes( array $methodes ): array {
		return Hardening::actif( 'xmlrpc' ) ? array() : $methodes;
	}

	/**
	 * Remplace le message d'erreur de connexion par un message unique.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param string $message Message construit par WordPress.
	 */
	public static function message_generique( string $message ): string {
		return Hardening::actif( 'divulgation' ) ? self::MESSAGE_CONNEXION : $message;
	}
}
