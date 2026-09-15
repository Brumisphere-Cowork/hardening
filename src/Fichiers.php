<?php
/**
 * Interdiction de l'éditeur de fichiers de l'administration.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Retire l'éditeur de code de l'administration, sans toucher aux mises à jour.
 *
 * L'éditeur de thèmes et d'extensions transforme un compte administrateur compromis en
 * exécution de code arbitraire sur le serveur, sans qu'aucune faille logicielle ne soit
 * nécessaire. Il contredit aussi la chaîne de déploiement : un fichier modifié depuis
 * l'administration est écrasé au déploiement suivant, et la modification est perdue
 * sans trace.
 *
 * Le module passe par le filtre file_mod_allowed plutôt que par la constante
 * DISALLOW_FILE_EDIT, pour deux raisons : il n'entre pas en conflit avec un wp-config.php
 * qui la définirait déjà, et il permet de ne viser que le contexte de l'édition.
 *
 * DISALLOW_FILE_MODS n'est volontairement pas posé. Cette constante couperait aussi les
 * mises à jour depuis l'administration, donc celles de Flatsome et d'ACF Pro, dont le
 * système de mise à jour repose sur un code d'achat enregistré en base de données. Le
 * durcissement casserait alors la chaîne de mise à jour des deux produits sous licence
 * du parc.
 */
final class Fichiers {

	/**
	 * Contexte interrogé par WordPress pour l'éditeur de thèmes et d'extensions.
	 */
	private const CONTEXTE_EDITION = 'capability_edit_themes';

	/**
	 * Branche le module.
	 */
	public static function enregistrer(): void {
		add_filter( 'file_mod_allowed', array( self::class, 'interdire_edition' ), 10, 2 );
	}

	/**
	 * Refuse la modification de fichiers dans le contexte de l'édition.
	 *
	 * Public car branché sur un filtre ; ne pas appeler directement.
	 *
	 * Tout autre contexte est transmis inchangé : installation et mise à jour des
	 * thèmes et des extensions restent possibles.
	 *
	 * @param bool   $autorise Décision courante.
	 * @param string $contexte Contexte interrogé par WordPress.
	 */
	public static function interdire_edition( bool $autorise, string $contexte ): bool {
		if ( ! Hardening::actif( 'edition_fichiers' ) ) {
			return $autorise;
		}

		return self::CONTEXTE_EDITION === $contexte ? false : $autorise;
	}
}
