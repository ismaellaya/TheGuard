#!/bin/bash

# Log de actualización
LOG_FILE="/var/log/theguard_update.log"
exec 1> >(tee -a "$LOG_FILE") 2>&1

echo "[+] Iniciando actualización de firmas $(date)"

# Directorio de backup
BACKUP_DIR="/etc/snort/backup"
mkdir -p "$BACKUP_DIR"

# Hacer backup de las reglas actuales
echo "[+] Creando backup de reglas actuales..."
cp /etc/snort/rules/local.rules "$BACKUP_DIR/local.rules.$(date +%Y%m%d)"

# Actualizar reglas personalizadas
echo "[+] Actualizando reglas personalizadas..."
cp config/snort/local.rules /etc/snort/rules/

# Verificar la sintaxis de las reglas
echo "[+] Verificando sintaxis de las reglas..."
if ! snort -T -c /etc/snort/snort.conf; then
    echo "[!] Error en la sintaxis de las reglas. Restaurando backup..."
    cp "$BACKUP_DIR/local.rules.$(date +%Y%m%d)" /etc/snort/rules/local.rules
    exit 1
fi

# Reiniciar Snort para aplicar los cambios
echo "[+] Reiniciando servicio Snort..."
systemctl restart snort

# Verificar que Snort está funcionando
if systemctl is-active --quiet snort; then
    echo "[+] Actualización completada exitosamente"
else
    echo "[!] Error: Snort no se pudo reiniciar"
    exit 1
fi

# Limpiar backups antiguos (mantener últimos 7 días)
find "$BACKUP_DIR" -name "local.rules.*" -mtime +7 -delete

echo "[+] Proceso de actualización finalizado"