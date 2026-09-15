<?php
/**
 * Doubles définis dans le namespace du paquet.
 *
 * PHP résout un appel de fonction non qualifié d'abord dans le namespace courant, puis
 * dans l'espace global. Une fonction interne comme header() ne peut pas être redéfinie
 * globalement, mais elle peut être doublée ici : les appels émis depuis le code du
 * paquet atteindront ce double, et non la fonction interne.
 *
 * @package Brumisphere\Hardening
 */

declare(strict_types=1);

namespace Brumisphere\Hardening;

/**
 * Double de header() : enregistre au lieu d'émettre.
 *
 * @param string $entete   En-tête complet, « Nom: valeur ».
 * @param bool   $remplace Remplace un en-tête de même nom.
 */
function header( string $entete, bool $remplace = true ): void {
	$GLOBALS['bru']['entetes_envoyes'][] = $entete;
}

/**
 * Double de headers_sent() : renvoie l'état simulé par le test.
 */
function headers_sent(): bool {
	return (bool) $GLOBALS['bru']['headers_sent'];
}
