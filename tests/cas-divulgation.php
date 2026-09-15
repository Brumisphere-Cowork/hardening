<?php
/**
 * Divulgation d'informations et XML-RPC.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

use Brumisphere\Hardening\Divulgation;
use Brumisphere\Hardening\Hardening;

bru_cas(
	'xmlrpc.php est reconnu, y compris déguisé',
	static function (): void {
		$hostiles = array(
			'/homepages/12/d1234/htdocs/acme/production/xmlrpc.php' => true,
			'/var/www/XMLRPC.PHP'                                   => true,
			'/var/www/XmlRpc.php'                                   => true,
			'C:\\inetpub\\site\\xmlrpc.php'                         => true,
			'/var/www/index.php'                                    => false,
			'/var/www/xmlrpc.php.bak'                               => false,
			'/var/www/my-xmlrpc.php'                                => false,
			'/var/www/xmlrpc.php/../index.php'                      => false,
			''                                                      => false,
		);

		foreach ( $hostiles as $script => $attendu ) {
			bru_egal(
				$attendu,
				Divulgation::est_requete_xmlrpc( (string) $script ),
				'détection pour ' . var_export( $script, true )
			);
		}
	}
);

bru_cas(
	'XML-RPC est déclaré désactivé et vidé de ses méthodes',
	static function (): void {
		Hardening::boot();

		bru_faux( Divulgation::xmlrpc_desactive( true ), 'xmlrpc_enabled renvoie false' );
		bru_egal( array(), Divulgation::vider_methodes( array( 'system.listMethods' => 'rappel' ) ), 'aucune méthode ne subsiste' );
	}
);

bru_cas(
	'XML-RPC reste intact si le module est désactivé',
	static function (): void {
		Hardening::boot( array( 'xmlrpc' => false ) );

		bru_vrai( Divulgation::xmlrpc_desactive( true ), 'l’état d’origine est transmis' );
		bru_egal(
			array( 'system.listMethods' => 'rappel' ),
			Divulgation::vider_methodes( array( 'system.listMethods' => 'rappel' ) ),
			'les méthodes sont transmises telles quelles'
		);
	}
);

bru_cas(
	'la balise générateur est vidée',
	static function (): void {
		Hardening::boot();

		bru_egal(
			'',
			Divulgation::masquer_generateur( '<meta name="generator" content="WordPress 6.8.1" />' ),
			'la version de WordPress ne sort plus'
		);
	}
);

bru_cas(
	'X-Pingback est retiré sans toucher au reste',
	static function (): void {
		Hardening::boot();

		$entetes = Divulgation::retirer_pingback(
			array(
				'X-Pingback'   => 'https://exemple.fr/xmlrpc.php',
				'Content-Type' => 'text/html; charset=UTF-8',
			)
		);

		bru_faux( isset( $entetes['X-Pingback'] ), 'X-Pingback est retiré' );
		bru_egal( 'text/html; charset=UTF-8', $entetes['Content-Type'] ?? null, 'les autres en-têtes sont préservés' );
	}
);

bru_cas(
	'le message de connexion ne distingue plus les causes',
	static function (): void {
		Hardening::boot();

		$natifs = array(
			'<strong>Erreur</strong> : l’identifiant « admin » n’est pas enregistré sur ce site.',
			'<strong>Erreur</strong> : le mot de passe saisi pour l’identifiant admin est incorrect.',
		);

		$reponses = array();

		foreach ( $natifs as $natif ) {
			$reponse    = Divulgation::message_generique( $natif );
			$reponses[] = $reponse;

			bru_faux( str_contains( $reponse, 'admin' ), 'aucun identifiant n’est renvoyé' );
			bru_faux( str_contains( $reponse, 'enregistré' ), 'la cause de l’échec n’est pas révélée' );
		}

		bru_egal( 1, count( array_unique( $reponses ) ), 'les deux causes donnent le même message' );
	}
);

bru_cas(
	'les liens de découverte sont retirés de l’en-tête',
	static function (): void {
		Hardening::boot();
		Divulgation::nettoyer_entete();

		foreach ( array( 'wp_head:wp_generator', 'wp_head:rsd_link', 'wp_head:wlwmanifest_link' ) as $retrait ) {
			bru_vrai( in_array( $retrait, $GLOBALS['bru']['retraits'], true ), $retrait . ' est retiré' );
		}
	}
);

bru_cas(
	'module désactivé, l’en-tête est laissé intact',
	static function (): void {
		Hardening::boot( array( 'divulgation' => false ) );
		Divulgation::nettoyer_entete();

		bru_egal( array(), $GLOBALS['bru']['retraits'], 'aucun retrait n’est effectué' );
	}
);
