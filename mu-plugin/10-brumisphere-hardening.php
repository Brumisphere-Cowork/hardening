<?php
/**
 * Plugin Name: Brumisphère — Durcissement
 * Description: Amorce le paquet brumisphere/hardening. Actif quel que soit le thème.
 * Version:     1.0.0
 * Author:      Brumisphère
 *
 * Fichier à déposer dans wp-content/mu-plugins/.
 *
 * Le préfixe 10- garantit qu'il est chargé après 00-autoload.php, qui met en place
 * l'autoloader de Composer. WordPress charge les mu-plugins dans l'ordre alphabétique
 * de leurs noms de fichiers.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( \Brumisphere\Hardening\Hardening::class ) ) {
	// L'autoloader n'est pas en place : le site fonctionne, mais sans durcissement.
	// Le signaler dans le journal plutôt que d'échouer silencieusement.
	error_log( 'Brumisphere\Hardening est introuvable : vérifier 00-autoload.php et composer install.' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log

	return;
}

\Brumisphere\Hardening\Hardening::boot();
