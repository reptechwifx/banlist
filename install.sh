#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="banlist"
SERVICE_UNIT="${SERVICE_NAME}.service"
SERVICE_DEST="/etc/systemd/system/${SERVICE_UNIT}"

echo "=== Installation du service ${SERVICE_NAME} ==="

# 1. Vérifier que l'on est root
if [[ "$(id -u)" -ne 0 ]]; then
    echo "Erreur : ce script doit être exécuté en root (sudo)."
    exit 1
fi

# 2. Déterminer le répertoire du script (là où se trouvent les fichiers)
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# 3. Vérifier la présence du fichier de service
if [[ ! -f "${SCRIPT_DIR}/${SERVICE_UNIT}" ]]; then
    echo "Erreur : fichier ${SERVICE_UNIT} introuvable dans ${SCRIPT_DIR}"
    exit 1
fi

# 4. Demander le port pour la web UI
read -r -p "Port HTTP à utiliser pour l’interface web [8080] : " WEB_PORT
WEB_PORT="${WEB_PORT:-8080}"

echo "→ Port sélectionné : ${WEB_PORT}"

# 5. Générer une copie modifiée du service avec le bon port
TMP_SERVICE="$(mktemp)"
sed "s|--port [0-9]\+|--port ${WEB_PORT}|g" \
    "${SCRIPT_DIR}/${SERVICE_UNIT}" > "${TMP_SERVICE}"

# Vérification : si rien n’a été remplacé, on injecte l’argument
if ! grep -q "${WEB_PORT}" "${TMP_SERVICE}"; then
    sed -i "s|ExecStart=.*python3 .*|& --port ${WEB_PORT}|g" "${TMP_SERVICE}"
fi

echo "✔ Injection du port dans le service systemd"

# 6. Copier vers /etc/systemd/system
echo "→ Installation du service dans ${SERVICE_DEST}"
cp "${TMP_SERVICE}" "${SERVICE_DEST}"
chmod 644 "${SERVICE_DEST}"
rm "${TMP_SERVICE}"

# 7. Recharger systemd
echo "→ Rechargement de systemd..."
systemctl daemon-reload

# 8. Activer au démarrage
echo "→ Activation du service..."
systemctl enable "${SERVICE_NAME}.service"

# 9. Démarrer le service
echo "→ Démarrage du service..."
systemctl restart "${SERVICE_NAME}.service"

# 10. État du service
echo "=== État du service ==="
systemctl --no-pager --full status "${SERVICE_NAME}.service" || true

echo "=== Installation terminée. ==="
echo "Web UI disponible sur : http://$(hostname -I | awk '{print $1}'):${WEB_PORT}/"
