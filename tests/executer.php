<?php
/**
 * Exécuteur de la suite de tests.
 *
 * Usage : php tests/executer.php
 *
 * Aucune dépendance externe. La suite vérifie des fonctions de rappel pures et le
 * branchement des accroches ; un cadre de test complet n'apporterait rien ici et
 * ajouterait une dépendance à installer avant de pouvoir vérifier quoi que ce soit.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

/**
 * Compteurs de la session.
 *
 * @var array<string, int>
 */
$GLOBALS['bru_resultats'] = array(
	'reussis' => 0,
	'echecs'  => 0,
);

/**
 * Échec d'assertion.
 */
final class BruEchec extends \RuntimeException {
}

/**
 * Exécute un cas de test.
 *
 * @param string   $nom Description du cas.
 * @param callable $cas Corps du test.
 */
function bru_cas( string $nom, callable $cas ): void {
	bru_reinitialiser();

	try {
		$cas();
		++$GLOBALS['bru_resultats']['reussis'];
		echo "  ok   " . $nom . PHP_EOL;
	} catch ( BruEchec $echec ) {
		++$GLOBALS['bru_resultats']['echecs'];
		echo "  ECHEC " . $nom . PHP_EOL;
		echo "        " . $echec->getMessage() . PHP_EOL;
	} catch ( \Throwable $erreur ) {
		++$GLOBALS['bru_resultats']['echecs'];
		echo "  ERREUR " . $nom . PHP_EOL;
		echo "        " . get_class( $erreur ) . ' : ' . $erreur->getMessage() . PHP_EOL;
	}
}

/**
 * Vérifie une égalité stricte.
 *
 * @param mixed  $attendu Valeur attendue.
 * @param mixed  $obtenu  Valeur obtenue.
 * @param string $message Description de l'attente.
 */
function bru_egal( $attendu, $obtenu, string $message ): void {
	if ( $attendu !== $obtenu ) {
		throw new BruEchec(
			$message . ' — attendu ' . var_export( $attendu, true ) . ', obtenu ' . var_export( $obtenu, true )
		);
	}
}

/**
 * Vérifie qu'une condition est vraie.
 *
 * @param bool   $condition Condition évaluée.
 * @param string $message   Description de l'attente.
 */
function bru_vrai( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new BruEchec( $message );
	}
}

/**
 * Vérifie qu'une condition est fausse.
 *
 * @param bool   $condition Condition évaluée.
 * @param string $message   Description de l'attente.
 */
function bru_faux( bool $condition, string $message ): void {
	bru_vrai( ! $condition, $message );
}

/**
 * Indique si une accroche porte un rappel de la classe indiquée.
 *
 * @param string $type     'actions' ou 'filtres'.
 * @param string $accroche Nom de l'accroche.
 * @param string $classe   Classe attendue.
 * @param string $methode  Méthode attendue.
 */
function bru_branche( string $type, string $accroche, string $classe, string $methode ): bool {
	foreach ( $GLOBALS['bru'][ $type ][ $accroche ] ?? array() as $entree ) {
		if ( is_array( $entree[0] ) && $classe === $entree[0][0] && $methode === $entree[0][1] ) {
			return true;
		}
	}

	return false;
}

$fichiers = glob( __DIR__ . '/cas-*.php' );

foreach ( false === $fichiers ? array() : $fichiers as $fichier ) {
	echo PHP_EOL . basename( $fichier ) . PHP_EOL;
	require_once $fichier;
}

echo PHP_EOL;
echo $GLOBALS['bru_resultats']['reussis'] . ' réussis, ' . $GLOBALS['bru_resultats']['echecs'] . ' en échec' . PHP_EOL;

exit( $GLOBALS['bru_resultats']['echecs'] > 0 ? 1 : 0 );
