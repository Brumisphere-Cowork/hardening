#!/usr/bin/env bash
#
# Contrôles d'intégration du durcissement, à exécuter contre un site réel.
#
#   ./tests/integration.sh https://mon-site.ddev.site
#
# À rejouer après bascule du site sur un thème par défaut : les résultats doivent être
# identiques. C'est le test de vérification de la répartition du code — un contrôle de
# sécurité qui change de résultat en changeant de thème est au mauvais endroit.

set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "Usage : $0 <url-du-site>" >&2
	exit 2
fi

BASE="${1%/}"
ECHECS=0

verifier() {
	local libelle="$1"
	local attendu="$2"
	local obtenu="$3"

	if [ "$attendu" = "$obtenu" ]; then
		printf '  ok    %s\n' "$libelle"
	else
		printf '  ECHEC %s — attendu %s, obtenu %s\n' "$libelle" "$attendu" "$obtenu"
		ECHECS=$((ECHECS + 1))
	fi
}

code_http() {
	curl -s -o /dev/null -w '%{http_code}' -L --max-redirs 3 "$1"
}

entete() {
	curl -sI "$BASE/" | tr -d '\r' | grep -i "^$1:" | head -n 1 | cut -d' ' -f2- || true
}

echo "Contrôles sur $BASE"

verifier "X-Content-Type-Options"  "nosniff"                          "$(entete 'X-Content-Type-Options')"
verifier "Referrer-Policy"         "strict-origin-when-cross-origin"  "$(entete 'Referrer-Policy')"
verifier "X-Frame-Options"         "SAMEORIGIN"                       "$(entete 'X-Frame-Options')"

# X-Pingback ne doit plus être annoncé.
verifier "X-Pingback retiré"       ""                                 "$(entete 'X-Pingback')"

# XML-RPC : la requête est arrêtée avant WordPress, donc 403 et non 405.
verifier "xmlrpc.php"              "403"                              "$(code_http "$BASE/xmlrpc.php")"

# Énumération : l'archive d'auteur et le point REST des utilisateurs.
verifier "/?author=1"              "404"                              "$(code_http "$BASE/?author=1")"
verifier "/wp-json/wp/v2/users"    "404"                              "$(code_http "$BASE/wp-json/wp/v2/users")"

# La version de WordPress ne doit pas apparaître dans la source.
GENERATEUR="$(curl -s "$BASE/" | grep -c 'name="generator"' || true)"
verifier "balise generator"        "0"                                "$GENERATEUR"

# Le reste du site doit continuer de répondre.
verifier "page d'accueil"          "200"                              "$(code_http "$BASE/")"
verifier "/wp-json/wp/v2/posts"    "200"                              "$(code_http "$BASE/wp-json/wp/v2/posts")"

echo
echo "Contrôles restants, à faire à la main dans l'administration :"
echo "  - téléverser un fichier nommé shell.php.jpg : il doit être refusé"
echo "  - Apparence : l'éditeur de fichiers de thème ne doit pas apparaître"
echo "  - Extensions : la mise à jour d'une extension doit rester possible"
echo "  - wp-login.php : un identifiant inexistant et un mot de passe erroné"
echo "    doivent produire exactement le même message"

if [ "$ECHECS" -gt 0 ]; then
	echo
	echo "$ECHECS contrôle(s) en échec." >&2
	exit 1
fi

echo
echo "Tous les contrôles automatiques sont au vert."
