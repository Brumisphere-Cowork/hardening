<?php
/**
 * Point d'entrée du durcissement partagé Brumisphère.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

defined( 'ABSPATH' ) || exit;

/**
 * Amorce les modules de durcissement.
 *
 * Ce paquet ne dépend d'aucun thème. Il est chargé par un mu-plugin, avant les
 * extensions, et reste actif si le site bascule sur un thème par défaut. C'est le test
 * de vérification de la répartition du code : si un contrôle de sécurité change de
 * résultat en changeant de thème, c'est qu'il est au mauvais endroit.
 *
 * Les modules branchent leurs accroches dès l'amorce, mais chaque rappel vérifie son
 * interrupteur au moment où il s'exécute. Les options sont donc résolues tard, ce qui
 * laisse à un mu-plugin de site chargé après celui-ci la possibilité de les modifier
 * par le filtre brumisphere/hardening/options.
 */
final class Hardening {

	/**
	 * Version du paquet.
	 */
	public const VERSION = '1.0.17';

	/**
	 * Empêche une double amorce si le mu-plugin est inclus deux fois.
	 *
	 * @var bool
	 */
	private static bool $amorce = false;

	/**
	 * Surcharges fournies à l'amorce, avant résolution.
	 *
	 * @var array<string, bool>
	 */
	private static array $surcharges = array();

	/**
	 * Options résolues, ou null tant que la résolution n'a pas eu lieu.
	 *
	 * @var array<string, bool>|null
	 */
	private static ?array $options = null;

	/**
	 * Amorce le durcissement.
	 *
	 * @param array<string, bool> $surcharges Interrupteurs imposés par le site.
	 */
	public static function boot( array $surcharges = array() ): void {
		if ( self::$amorce ) {
			return;
		}

		self::$amorce     = true;
		self::$surcharges = $surcharges;

		Entetes::enregistrer();
		Divulgation::enregistrer();
		Enumeration::enregistrer();
		Fichiers::enregistrer();
		Coeur::enregistrer();
		Televersement::enregistrer();
	}

	/**
	 * Indique si un interrupteur est actif.
	 *
	 * Une clé inconnue renvoie false : un module retiré du paquet ne doit pas se
	 * réactiver silencieusement parce qu'un site a gardé une option orpheline.
	 *
	 * @param string $cle Nom de l'interrupteur.
	 */
	public static function actif( string $cle ): bool {
		if ( null === self::$options ) {
			self::resoudre();
		}

		return self::$options[ $cle ] ?? false;
	}

	/**
	 * Interrupteurs livrés par défaut.
	 *
	 * Tous actifs. La recette de sécurité d'un site livré exige ces contrôles : un
	 * durcissement qu'il faut penser à allumer n'est pas allumé.
	 *
	 * @return array<string, bool>
	 */
	public static function defauts(): array {
		return array(
			'entetes'          => true,
			'entetes_hsts'     => true,
			'divulgation'      => true,
			'xmlrpc'           => true,
			'enumeration'      => true,
			'edition_fichiers' => true,
			'maj_coeur'        => true,
			'televersement'    => true,
		);
	}

	/**
	 * Réinitialise l'état interne.
	 *
	 * Réservé à la suite de tests, qui doit pouvoir rejouer une amorce avec d'autres
	 * options dans le même processus. Sans usage en production.
	 */
	public static function reinitialiser(): void {
		self::$amorce     = false;
		self::$surcharges = array();
		self::$options    = null;
	}

	/**
	 * Fusionne les valeurs par défaut, les surcharges du site, puis le filtre.
	 *
	 * Seules les clés connues sont conservées, et chaque valeur est ramenée à un
	 * booléen : une option mal typée ne doit pas produire un comportement indécis.
	 */
	private static function resoudre(): void {
		$options = self::defauts();

		foreach ( self::$surcharges as $cle => $valeur ) {
			if ( array_key_exists( $cle, $options ) ) {
				$options[ $cle ] = (bool) $valeur;
			}
		}

		/**
		 * Filtre les interrupteurs du durcissement.
		 *
		 * @param array<string, bool> $options Interrupteurs résolus.
		 */
		$filtrees = apply_filters( 'brumisphere/hardening/options', $options );

		if ( is_array( $filtrees ) ) {
			foreach ( $filtrees as $cle => $valeur ) {
				if ( is_string( $cle ) && array_key_exists( $cle, $options ) ) {
					$options[ $cle ] = (bool) $valeur;
				}
			}
		}

		self::$options = $options;
	}
}
