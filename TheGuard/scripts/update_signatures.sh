#!/bin/bash

# Log de actualización
LOG_FILE="/var/log/theguard_update.log"
exec 1> >(tee -a "$LOG_FILE") 2>&1

echo "[+] Iniciando actualización de firmas $(date)"

# Directorio de backup
BACKUP_DIR="/etc/suricata/backup"
mkdir -p "$BACKUP_DIR"

# Hacer backup de las reglas actuales
echo "[+] Creando backup de reglas actuales..."
cp /etc/suricata/rules/custom_rules.rules "$BACKUP_DIR/custom_rules.rules.$(date +%Y%m%d)"

# Actualizar reglas de Suricata
echo "[+] Actualizando reglas oficiales de Suricata..."
suricata-update

# Actualizar reglas personalizadas
echo "[+] Actualizando reglas personalizadas..."
cp modules/ids_signatures/rules/custom_rules.rules /etc/suricata/rules/

# Verificar la sintaxis de las reglas
echo "[+] Verificando sintaxis de las reglas..."
if ! suricata -T -c /etc/suricata/suricata.yaml -v; then
    echo "[!] Error en la sintaxis de las reglas. Restaurando backup..."
    cp "$BACKUP_DIR/custom_rules.rules.$(date +%Y%m%d)" /etc/suricata/rules/custom_rules.rules
    exit 1
fi

# Reiniciar Suricata para aplicar los cambios
echo "[+] Reiniciando servicio Suricata..."
systemctl restart suricata

# Verificar que Suricata está funcionando
if systemctl is-active --quiet suricata; then
    echo "[+] Actualización completada exitosamente"
else
    echo "[!] Error: Suricata no se pudo reiniciar"
    exit 1
fi

# Limpiar backups antiguos (mantener últimos 7 días)
find "$BACKUP_DIR" -name "custom_rules.rules.*" -mtime +7 -delete

echo "[+] Proceso de actualización finalizado"