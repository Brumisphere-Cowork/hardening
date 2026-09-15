<?php
/**
 * Socle de la suite de tests : doubles de WordPress et outils d'assertion.
 *
 * Les modules de durcissement sont des fonctions de rappel branchées sur des accroches.
 * Les tester ne demande pas une installation de WordPress, mais des doubles des quelques
 * fonctions qu'ils appellent, et un registre qui note ce qui a été branché.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

define( 'ABSPATH', __DIR__ . '/' );

spl_autoload_register(
	static function ( string $classe ): void {
		$prefixe = 'Brumisphere\\Hardening\\';

		if ( ! str_starts_with( $classe, $prefixe ) ) {
			return;
		}

		$fichier = dirname( __DIR__ ) . '/src/' . substr( $classe, strlen( $prefixe ) ) . '.php';

		if ( is_file( $fichier ) ) {
			require_once $fichier;
		}
	}
);

/**
 * État observable des doubles.
 *
 * @var array<string, mixed>
 */
$GLOBALS['bru'] = array();

/**
 * Remet les doubles dans leur état initial.
 */
function bru_reinitialiser(): void {
	$GLOBALS['bru'] = array(
		'actions'           => array(),
		'filtres'           => array(),
		'retraits'          => array(),
		'entetes_envoyes'   => array(),
		'statut'            => 0,
		'is_ssl'            => false,
		'is_author'         => false,
		'is_user_logged_in' => false,
		'headers_sent'      => false,
	);

	\Brumisphere\Hardening\Hardening::reinitialiser();
}

// ---------------------------------------------------------------------------
// Doubles des fonctions WordPress, portée globale.
// ---------------------------------------------------------------------------

/**
 * Enregistre une action.
 *
 * @param string   $accroche Nom de l'accroche.
 * @param callable $rappel   Fonction de rappel.
 * @param int      $priorite Priorité.
 * @param int      $arguments Nombre d'arguments acceptés.
 */
function add_action( string $accroche, $rappel, int $priorite = 10, int $arguments = 1 ): void {
	$GLOBALS['bru']['actions'][ $accroche ][] = array( $rappel, $priorite, $arguments );
}

/**
 * Enregistre un filtre.
 *
 * @param string   $accroche Nom de l'accroche.
 * @param callable $rappel   Fonction de rappel.
 * @param int      $priorite Priorité.
 * @param int      $arguments Nombre d'arguments acceptés.
 */
function add_filter( string $accroche, $rappel, int $priorite = 10, int $arguments = 1 ): void {
	$GLOBALS['bru']['filtres'][ $accroche ][] = array( $rappel, $priorite, $arguments );
}

/**
 * Note un retrait d'action.
 *
 * @param string $accroche Nom de l'accroche.
 * @param string $rappel   Fonction retirée.
 * @param int    $priorite Priorité.
 */
function remove_action( string $accroche, $rappel, int $priorite = 10 ): void {
	$GLOBALS['bru']['retraits'][] = $accroche . ':' . ( is_string( $rappel ) ? $rappel : '?' );
}

/**
 * Applique les filtres enregistrés.
 *
 * @param string $accroche Nom de l'accroche.
 * @param mixed  $valeur   Valeur initiale.
 * @param mixed  ...$reste Arguments supplémentaires.
 * @return mixed
 */
function apply_filters( string $accroche, $valeur, ...$reste ) {
	foreach ( $GLOBALS['bru']['filtres'][ $accroche ] ?? array() as $entree ) {
		$valeur = call_user_func_array( $entree[0], array_merge( array( $valeur ), $reste ) );
	}

	return $valeur;
}

/**
 * Indique si la requête est en HTTPS.
 */
function is_ssl(): bool {
	return (bool) $GLOBALS['bru']['is_ssl'];
}

/**
 * Indique si la requête vise une archive d'auteur.
 */
function is_author(): bool {
	return (bool) $GLOBALS['bru']['is_author'];
}

/**
 * Indique si un utilisateur est connecté.
 */
function is_user_logged_in(): bool {
	return (bool) $GLOBALS['bru']['is_user_logged_in'];
}

/**
 * Note le code de statut HTTP.
 *
 * @param int $code Code HTTP.
 */
function status_header( int $code ): void {
	$GLOBALS['bru']['statut'] = $code;
}

/**
 * Double sans effet.
 */
function nocache_headers(): void {
}

/**
 * Double de l'assainissement de WordPress, suffisant pour les tests.
 *
 * @param string $valeur Valeur brute.
 */
function sanitize_text_field( string $valeur ): string {
	return trim( strip_tags( $valeur ) );
}

/**
 * Double du retrait des antislashs.
 *
 * @param string $valeur Valeur brute.
 */
function wp_unslash( string $valeur ): string {
	return stripslashes( $valeur );
}

/**
 * Double de l'échappement HTML.
 *
 * @param string $valeur Valeur brute.
 */
function esc_html( string $valeur ): string {
	return htmlspecialchars( $valeur, ENT_QUOTES, 'UTF-8' );
}

/**
 * Requête WordPress, réduite à ce que le module utilise.
 */
class WP_Query { // phpcs:ignore

	/**
	 * Vrai si set_404 a été appelée.
	 */
	public bool $est_404 = false;

	/**
	 * Marque la requête comme introuvable.
	 */
	public function set_404(): void {
		$this->est_404 = true;
	}
}

// header() est une fonction interne, elle ne peut pas être redéfinie globalement.
// Le double vit donc dans le namespace du paquet, où PHP le résout en priorité.
require_once __DIR__ . '/doubles-namespace.php';
