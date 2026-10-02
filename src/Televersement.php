<?php
/**
 * Restriction des fichiers acceptés dans la médiathèque.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Refuse les fichiers exécutables et les images vectorielles non assainies.
 *
 * Deux risques distincts sont traités ici.
 *
 * Un fichier PHP déposé dans la médiathèque est directement adressable par son URL. Si
 * la configuration du serveur l'exécute, le dépôt d'un fichier vaut exécution de code.
 * WordPress vérifie déjà le type réel d'une image, mais des extensions ajoutent des
 * types au fil de l'eau, et un nom à double extension continue de circuler comme
 * tentative. Le contrôle porte donc sur toutes les extensions du nom, pas seulement la
 * dernière.
 *
 * Un SVG est un document XML qui peut contenir du script, exécuté dans le contexte du
 * domaine à l'ouverture du fichier. WordPress ne l'accepte pas par défaut ; ce module
 * le retire à nouveau, car une extension a pu l'ajouter. Un site qui a réellement
 * besoin du SVG doit d'abord installer un assainisseur, puis désactiver ce module.
 *
 * Ce retrait se fait à la priorité 10 : un thème ou une extension branché après lui peut
 * remettre le SVG. L'interrupteur svg_restreint, éteint par défaut, ajoute un second
 * contrôle à la priorité PHP_INT_MAX, qui retire le SVG aux seuls comptes sans
 * unfiltered_html, comme WordPress le fait pour le HTML et le JavaScript. Un site qui
 * réserve le SVG à ses administrateurs, pour un logo vectoriel par exemple, l'allume.
 */
final class Televersement {

	/**
	 * Extensions refusées, où qu'elles apparaissent dans le nom.
	 */
	private const EXTENSIONS_INTERDITES = array(
		'php',
		'php3',
		'php4',
		'php5',
		'php7',
		'php8',
		'phps',
		'phtml',
		'phar',
		'htaccess',
	);

	/**
	 * Extensions retirées de la liste des types acceptés.
	 */
	private const EXTENSIONS_RETIREES = array( 'svg', 'svgz' );

	/**
	 * Priorité du contrôle svg_restreint : après les thèmes et les extensions.
	 */
	private const PRIORITE_SVG_RESTREINT = PHP_INT_MAX;

	/**
	 * Branche le module.
	 */
	public static function enregistrer(): void {
		add_filter( 'upload_mimes', array( self::class, 'retirer_svg' ) );
		add_filter( 'upload_mimes', array( self::class, 'restreindre_svg' ), self::PRIORITE_SVG_RESTREINT, 2 );
		add_filter( 'wp_handle_upload_prefilter', array( self::class, 'refuser_fichier_dangereux' ) );
	}

	/**
	 * Retire le SVG des types acceptés.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * Une clé de cette liste peut regrouper plusieurs extensions, sous la forme
	 * "svg|svgz". Retirer la clé exacte ne suffit donc pas.
	 *
	 * @param array<string, string> $types Extensions acceptées et leur type MIME.
	 * @return array<string, string>
	 */
	public static function retirer_svg( array $types ): array {
		if ( ! Hardening::actif( 'televersement' ) ) {
			return $types;
		}

		return self::sans_svg( $types );
	}

	/**
	 * Retire le SVG aux comptes qui n'ont pas unfiltered_html.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * Branché à PHP_INT_MAX, après les thèmes et les extensions qui ajoutent le SVG. La
	 * règle est celle de get_allowed_mime_types() pour le HTML et le JavaScript :
	 * l'utilisateur passé par WordPress s'il y en a un, l'utilisateur courant sinon.
	 *
	 * @param array<string, string> $types       Extensions acceptées et leur type MIME.
	 * @param int|\WP_User|null     $utilisateur Utilisateur passé par get_allowed_mime_types().
	 * @return array<string, string>
	 */
	public static function restreindre_svg( array $types, $utilisateur = null ): array {
		if ( ! Hardening::actif( 'svg_restreint' ) ) {
			return $types;
		}

		$confiance = $utilisateur ? user_can( $utilisateur, 'unfiltered_html' ) : current_user_can( 'unfiltered_html' );

		return $confiance ? $types : self::sans_svg( $types );
	}

	/**
	 * Retire toute clé qui contient svg ou svgz.
	 *
	 * Une clé de cette liste peut regrouper plusieurs extensions, sous la forme
	 * "svg|svgz". Retirer la clé exacte ne suffit donc pas.
	 *
	 * @param array<string, string> $types Extensions acceptées et leur type MIME.
	 * @return array<string, string>
	 */
	private static function sans_svg( array $types ): array {
		foreach ( array_keys( $types ) as $cle ) {
			$extensions = explode( '|', strtolower( (string) $cle ) );

			if ( array() !== array_intersect( $extensions, self::EXTENSIONS_RETIREES ) ) {
				unset( $types[ $cle ] );
			}
		}

		return $types;
	}

	/**
	 * Refuse un fichier dont le nom porte une extension exécutable.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * @param array<string, mixed> $fichier Entrée de $_FILES en cours de traitement.
	 * @return array<string, mixed>
	 */
	public static function refuser_fichier_dangereux( array $fichier ): array {
		if ( ! Hardening::actif( 'televersement' ) ) {
			return $fichier;
		}

		$nom = isset( $fichier['name'] ) ? (string) $fichier['name'] : '';

		if ( self::nom_dangereux( $nom ) ) {
			$fichier['error'] = 'Ce type de fichier n\'est pas accepté sur ce site.';
		}

		return $fichier;
	}

	/**
	 * Indique si un nom de fichier porte une extension exécutable.
	 *
	 * Le nom est d'abord réduit à son dernier segment, avec les deux séparateurs de
	 * chemin, pour qu'une valeur du type "../../shell.php" soit examinée comme
	 * "shell.php" et non comme un chemin.
	 *
	 * Un octet nul est refusé sans autre examen : il ne peut apparaître dans un nom
	 * légitime, et sert précisément à tronquer le nom après coup, du côté du système
	 * de fichiers.
	 *
	 * @param string $nom Nom de fichier soumis.
	 */
	public static function nom_dangereux( string $nom ): bool {
		if ( str_contains( $nom, "\0" ) ) {
			return true;
		}

		$base       = basename( str_replace( '\\', '/', strtolower( $nom ) ) );
		$morceaux   = explode( '.', $base );
		$extensions = array_slice( $morceaux, 1 );

		foreach ( $extensions as $extension ) {
			if ( in_array( trim( $extension ), self::EXTENSIONS_INTERDITES, true ) ) {
				return true;
			}
		}

		return false;
	}
}
