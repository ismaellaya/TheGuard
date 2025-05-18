#!/bin/bash

# Control de instancia única
LOCK_FILE="/var/run/suricata_setup.lock"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Verificar si ya hay una instalación en proceso
if [ -f "$LOCK_FILE" ]; then
    echo "[!] Ya hay un proceso de instalación en ejecución"
    exit 1
fi

# Crear archivo de bloqueo
touch "$LOCK_FILE"

# Agregar limpieza al final o en caso de error
cleanup() {
    rm -f "$LOCK_FILE"
}
trap cleanup EXIT

# Log de instalación
LOG_FILE="/var/log/theguard_suricata_setup.log"
mkdir -p "$(dirname "$LOG_FILE")"
exec 1> >(tee -a "$LOG_FILE") 2>&1

echo "[+] Iniciando instalación de Suricata $(date)"

# Verificar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Este script debe ejecutarse como root"
    exit 1
fi

# Verificar requisitos del sistema
check_requirements() {
    echo "[+] Verificando requisitos del sistema..."
    
    # Verificar memoria
    total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ $total_mem -lt 2048 ]; then
        echo "[!] Error: Se requieren al menos 2GB de RAM"
        exit 1
    fi
    
    # Verificar versión del kernel
    kernel_version=$(uname -r | cut -d. -f1)
    if [ $kernel_version -lt 4 ]; then
        echo "[!] Error: Se requiere kernel 4.x o superior"
        exit 1
    fi
    
    # Verificar espacio en disco
    MIN_SPACE=5000000  # 5GB en KB
    available_space=$(df /var/log | awk 'NR==2 {print $4}')
    if [ $available_space -lt $MIN_SPACE ]; then
        echo "[!] Error: Espacio insuficiente en disco"
        exit 1
    fi
    
    # Verificar archivo de configuración
    if [ ! -f "${PROJECT_ROOT}/config/suricata/suricata.yaml" ]; then
        echo "[!] Error: No se encuentra el archivo de configuración en ${PROJECT_ROOT}/config/suricata/suricata.yaml"
        exit 1
    fi
    
    # Verificar directorios de reglas
    if [ ! -d "${SCRIPT_DIR}/rules" ]; then
        echo "[!] Error: No se encuentra el directorio de reglas"
        exit 1
    fi
    
    # Verificar conectividad de red
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "[!] Error: No hay conectividad a Internet"
        exit 1
    fi
}

check_requirements

# Crear directorios necesarios
echo "[+] Creando directorios..."
mkdir -p /var/log/theguard/suricata
mkdir -p /var/lib/suricata/backup
mkdir -p /etc/suricata/rules/custom

# Instalar dependencias
echo "[+] Instalando dependencias..."
apt-get update
apt-get install -y suricata unrar-free

# Configurar usuario y grupo
if ! getent group suricata >/dev/null; then
    groupadd -r suricata
fi

if ! getent passwd suricata >/dev/null; then
    useradd -r -g suricata -s /sbin/nologin suricata
fi

# Hacer backup de la configuración existente
echo "[+] Realizando backup de configuración existente..."
if [ -f "/etc/suricata/suricata.yaml" ]; then
    cp /etc/suricata/suricata.yaml "/var/lib/suricata/backup/suricata.yaml.$(date +%Y%m%d_%H%M%S)"
fi

echo "[+] Extrayendo reglas…"
# Ruta real a tu archivo de reglas
RULES_ARCHIVE="${BASE_DIR}/ids_signatures/rules.rar"

if [ -f "$RULES_ARCHIVE" ]; then
    # Asegúrate de tener unrar no libre
    apt-get install -y unrar p7zip-rar

    # Extrae preservando la estructura
    unrar x "$RULES_ARCHIVE" /etc/suricata/rules/ \
      || { echo "[!] Error extrayendo $RULES_ARCHIVE"; exit 1; }

    # Ahora copiamos las configs y las reglas
    cp /etc/suricata/rules/emerging.rules/rules/classification.config \
       /etc/suricata/rules/ || true
    cp /etc/suricata/rules/emerging.rules/rules/reference.config \
       /etc/suricata/rules/ || true
    cp /etc/suricata/rules/emerging.rules/rules/*.rules \
       /etc/suricata/rules/

else
    echo "[!] Error: no encontré $RULES_ARCHIVE"
    exit 1
fi

    
    # Mover todas las reglas .rules al directorio principal
find rules/et_rules/emerging.rules/rules/ -name "*.rules" -exec cp {} . \;
    

   
    # Actualizar reglas de Suricata
echo -e "${YELLOW}[*] Actualizando reglas de Suricata...${NC}"
suricata-update
     # Copiar configuración personalizadas
echo -e "${YELLOW}[*] Instalando PRIMERA config personalizada ...${NC}"
cp "${PROJECT_ROOT}/config/suricata/suricata.yaml" /etc/suricata/

# Asignar permisos correctos
chown -R suricata:suricata /var/log/theguard/suricata
chown -R suricata:suricata /etc/suricata
chmod -R 750 /etc/suricata/rules

# Validar configuración
echo "[+] Validando configuración..."
suricata -T -c /etc/suricata/suricata.yaml

# Configurar servicio
echo "[+] Configurando servicio Suricata..."
systemctl enable suricata
systemctl restart suricata

# Configurar sistema de logging
echo "[+] Configurando sistema de logging..."
mkdir -p /var/log/theguard/suricata
chown -R suricata:suricata /var/log/theguard/suricata

# Configuración de logging mejorada
echo "[+] Configurando sistema de logging..."
cat > /etc/rsyslog.d/00-suricata.conf << EOF
if \$programname == 'suricata' then /var/log/theguard/suricata/suricata.log
& stop
EOF

# Configurar logrotate más detallado
cat > /etc/logrotate.d/theguard-suricata << EOF
/var/log/theguard/suricata/*.log {
    daily
    rotate 30
    compress
    delaycompress
    create 640 suricata suricata
    missingok
    dateext
    postrotate
        /bin/kill -HUP \$(cat /var/run/suricata.pid 2>/dev/null) 2>/dev/null || true
        systemctl reload rsyslog
    endscript
}
EOF

# Actualizar reglas de Suricata
echo "[+] Actualizando reglas..."
suricata-update

# Configurar monitoreo de recursos
echo "[+] Configurando monitoreo de recursos..."
if [ -f "${SCRIPT_DIR}/monitor_suricata.sh" ]; then
    cp "${SCRIPT_DIR}/monitor_suricata.sh" /usr/local/bin/
    chmod +x /usr/local/bin/monitor_suricata.sh
else
    echo "[!] Advertencia: No se encontró script de monitoreo"
fi

# Crear servicio de monitoreo
cat > /etc/systemd/system/suricata-monitor.service << EOF
[Unit]
Description=Suricata Resource Monitor
After=suricata.service

[Service]
Type=simple
ExecStart=/usr/local/bin/monitor_suricata.sh
Restart=always
StandardOutput=append:/var/log/theguard/suricata/monitor.log
StandardError=append:/var/log/theguard/suricata/monitor.log

[Install]
WantedBy=multi-user.target
EOF

# Script de backup automático
cat > /usr/local/bin/backup_suricata_rules.sh << EOF
#!/bin/bash
BACKUP_DIR="/var/lib/suricata/backup/rules"
mkdir -p \${BACKUP_DIR}

# Backup de reglas personalizadas
tar -czf \${BACKUP_DIR}/custom_rules_\$(date +%Y%m%d_%H%M%S).tar.gz /etc/suricata/rules/custom/

# Mantener solo los últimos 7 backups
find \${BACKUP_DIR} -type f -mtime +7 -delete
EOF

chmod +x /usr/local/bin/backup_suricata_rules.sh

# Configurar backup automático diario
echo "0 0 * * * root /usr/local/bin/backup_suricata_rules.sh" > /etc/cron.d/suricata-backup

# Configurar sistema de reportes
echo "[+] Configurando sistema de reportes..."
if [ -f "${SCRIPT_DIR}/suricata_report.sh" ]; then
    cp "${SCRIPT_DIR}/suricata_report.sh" /usr/local/bin/
    chmod +x /usr/local/bin/suricata_report.sh
else
    echo "[!] Advertencia: No se encontró script de reportes"
fi

# Configurar reporte diario
echo "0 6 * * * root /usr/local/bin/suricata_report.sh" > /etc/cron.d/suricata-report

# Verificar la configuración
echo "[+] Verificando configuración..."
suricata -T -c /etc/suricata/suricata.yaml

# Habilitar y reiniciar servicios
systemctl daemon-reload
systemctl enable suricata-monitor
systemctl start suricata-monitor
systemctl restart suricata
systemctl restart rsyslog

# Verificar estado final
if systemctl is-active --quiet suricata; then
    echo "[+] Suricata instalado y configurado correctamente"
    echo "[+] Logs principales en: /var/log/theguard/suricata/suricata.log"
    echo "[+] Logs de monitoreo en: /var/log/theguard/suricata/monitor.log"
    echo "[+] Reportes diarios en: /var/log/theguard/suricata/reports"
    echo "[+] Backups en: /var/lib/suricata/backup"
    echo "[+] Reglas personalizadas en: /etc/suricata/rules/custom"
else
    echo "[!] Error: Suricata no se pudo iniciar"
    exit 1
fi

echo "[+] Instalación completada exitosamente"
