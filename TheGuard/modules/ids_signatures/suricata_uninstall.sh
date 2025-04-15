#!/bin/bash

# Log de desinstalación
LOG_FILE="/var/log/theguard_suricata_uninstall.log"
exec 1> >(tee -a "$LOG_FILE") 2>&1

echo "[+] Iniciando desinstalación de Suricata $(date)"

# Verificar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Este script debe ejecutarse como root"
    exit 1
fi

# Detener servicios
echo "[+] Deteniendo servicios..."
systemctl stop suricata-monitor
systemctl stop suricata

# Deshabilitar servicios
echo "[+] Deshabilitando servicios..."
systemctl disable suricata-monitor
systemctl disable suricata

# Crear backup final
echo "[+] Creando backup final..."
BACKUP_DIR="/var/lib/suricata/backup/uninstall_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${BACKUP_DIR}"

# Backup de configuración y reglas
if [ -d "/etc/suricata" ]; then
    tar -czf "${BACKUP_DIR}/suricata_config.tar.gz" /etc/suricata/
fi

# Backup de logs
if [ -d "/var/log/theguard/suricata" ]; then
    tar -czf "${BACKUP_DIR}/suricata_logs.tar.gz" /var/log/theguard/suricata/
fi

# Eliminar archivos y directorios
echo "[+] Eliminando archivos..."
rm -f /etc/rsyslog.d/00-suricata.conf
rm -f /etc/logrotate.d/theguard-suricata
rm -f /etc/systemd/system/suricata-monitor.service
rm -f /usr/local/bin/monitor_suricata.sh
rm -f /usr/local/bin/backup_suricata_rules.sh
rm -f /etc/cron.d/suricata-backup

# Desinstalar Suricata
echo "[+] Desinstalando Suricata..."
apt-get remove -y suricata
apt-get autoremove -y

# Limpiar directorios (preservando backups)
echo "[+] Limpiando directorios..."
rm -rf /etc/suricata
rm -rf /var/log/theguard/suricata

echo "[+] Desinstalación completada"
echo "[+] Backup final guardado en: ${BACKUP_DIR}"
echo "[+] Log de desinstalación en: ${LOG_FILE}"