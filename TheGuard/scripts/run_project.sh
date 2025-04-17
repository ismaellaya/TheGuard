#!/bin/bash

# Definir la ruta base del proyecto
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Configurar colores para los mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Función para crear y configurar directorios
setup_directories() {
    echo -e "${YELLOW}[*] Creando estructura de directorios...${NC}"
    
    # Crear directorios principales
    mkdir -p "${BASE_DIR}/logs"
    mkdir -p /var/log/theguard/suricata
    mkdir -p /etc/suricata/rules
    mkdir -p /var/lib/suricata/backup
    mkdir -p "${BASE_DIR}/modules/ids_signatures/rules"
    mkdir -p "${BASE_DIR}/modules/anomaly_analysis/model/trained_models"
    
    # Configurar permisos
    chown -R root:root /var/log/theguard
    chmod -R 755 /var/log/theguard
    chown -R root:root /etc/suricata
    chmod -R 755 /etc/suricata
    
    # Crear directorio para archivos temporales
    mkdir -p /tmp/theguard
    chmod 777 /tmp/theguard
    
    echo -e "${GREEN}[+] Directorios creados y configurados correctamente${NC}"
}

echo -e "${GREEN}[+] Iniciando TheGuard...${NC}"

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi

# Crear y configurar directorios
setup_directories

# Configurar la Raspberry Pi como AP
setup_ap() {
    echo -e "${YELLOW}[*] Configurando modo Access Point...${NC}"
    
    # Instalar dependencias necesarias
    apt-get update
    apt-get install -y hostapd dnsmasq

    # Detener servicios para la configuración
    systemctl stop hostapd
    systemctl stop dnsmasq

    # Configurar interfaz wireless
    cat > /etc/dhcpcd.conf << EOF
interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
EOF

    # Configurar hostapd
    cat > /etc/hostapd/hostapd.conf << EOF
interface=wlan0
driver=nl80211
ssid=TheGuard_AP
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=TheGuard2024
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

    # Configurar dnsmasq
    cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
EOF

    # Habilitar IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p

    # Configurar NAT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # Guardar reglas de iptables
    iptables-save > /etc/iptables.ipv4.nat

    # Habilitar servicios
    systemctl unmask hostapd
    systemctl enable hostapd
    systemctl enable dnsmasq
    
    # Iniciar servicios
    systemctl start hostapd
    systemctl start dnsmasq
}

# Verificar y configurar Suricata si es necesario
setup_suricata() {
    # Verificar si Suricata ya está en ejecución
    if systemctl is-active --quiet suricata; then
        echo -e "${YELLOW}[*] Suricata ya está en ejecución${NC}"
        return
    fi

    # Verificar estado de instalación
    if [ ! -f "/etc/suricata/suricata.yaml" ]; then
        echo -e "${YELLOW}[*] Primera instalación detectada${NC}"
        bash "${BASE_DIR}/modules/ids_signatures/suricata_setup.sh"
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Error en la instalación inicial de Suricata${NC}"
            exit 1
        fi
    else
        # Configuración básica para arranques posteriores
        systemctl start suricata
    fi

    # Verificar estado final
    if ! systemctl is-active --quiet suricata; then
        echo -e "${RED}[!] Error: No se pudo iniciar Suricata${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Suricata configurado y ejecutando correctamente${NC}"
}

# Crear directorios necesarios
mkdir -p /var/log/theguard
mkdir -p /var/log/suricata

# Configurar AP
setup_ap

# Configurar Suricata
setup_suricata

# Copiar configuración personalizadas
echo -e "${YELLOW}[*] Instalando config personalizada...${NC}"
cp "${BASE_DIR}/config/suricata/suricata.yaml" /etc/suricata/

# Actualizar reglas de Suricata
echo -e "${YELLOW}[*] Actualizando reglas de Suricata...${NC}"
suricata-update

# Copiar reglas personalizadas
echo -e "${YELLOW}[*] Instalando reglas personalizadas...${NC}"
cp "${BASE_DIR}/modules/ids_signatures/rules/custom_rules.rules" /etc/suricata/rules/
cp "${BASE_DIR}/modules/ids_signatures/rules/et_rules/emerging.rules/rules/"*.rules /etc/suricata/rules/



systemctl restart suricata

# Iniciar el procesador de alertas de Suricata
echo -e "${YELLOW}[*] Iniciando sistema de monitoreo de alertas...${NC}"
PYTHONPATH="${BASE_DIR}" python3 -c "from modules.ids_signatures import get_ids_processor; get_ids_processor().start_monitoring()" &
echo $! > /var/run/theguard_alert_monitor.pid

# Iniciar todos los módulos
echo -e "${YELLOW}[*] Iniciando módulos...${NC}"

# Módulo 1 - IDS (Suricata ya está iniciado)

# Módulo 2 - Análisis de Anomalías
echo -e "${YELLOW}[*] Iniciando Módulo 2 (Análisis de Anomalías)...${NC}"
PYTHONPATH="${BASE_DIR}" python3 -c "from modules.anomaly_analysis import AnomalyModule; AnomalyModule().start()" &
echo $! > /var/run/theguard_anomaly.pid

# Módulo 3 - DPI
echo -e "${YELLOW}[*] Iniciando Módulo 3 (DPI)...${NC}"
PYTHONPATH="${BASE_DIR}" python3 -c "from modules.dpi import DPIModule; DPIModule().start()" &
echo $! > /var/run/theguard_dpi.pid

# Módulo 4 - IP Monitoring
echo -e "${YELLOW}[*] Iniciando Módulo 4 (IP Monitoring)...${NC}"
PYTHONPATH="${BASE_DIR}" python3 -c "from modules.ip_monitoring import IPMonitoringModule; IPMonitoringModule().start()" &
echo $! > /var/run/theguard_ip_monitoring.pid

# Módulo 5 - Dashboard
echo -e "${YELLOW}[*] Iniciando Dashboard...${NC}"
bash "${BASE_DIR}/scripts/start_dashboard.sh" &
echo $! > /var/run/theguard_dashboard.pid

# Función de limpieza actualizada
cleanup() {
    echo -e "${YELLOW}[*] Deteniendo servicios...${NC}"
    
    # Detener todos los módulos
    for pid_file in /var/run/theguard_*.pid; do
        if [ -f "$pid_file" ]; then
            kill $(cat "$pid_file")
            rm "$pid_file"
        fi
    done
    
    # Detener Suricata
    systemctl stop suricata
    
    # Detener servicios de AP
    systemctl stop hostapd
    systemctl stop dnsmasq
    
    echo -e "${GREEN}[+] Todos los módulos detenidos correctamente${NC}"
}

# Registrar función de limpieza para señales de terminación
trap cleanup SIGINT SIGTERM

echo -e "${GREEN}[+] TheGuard iniciado correctamente${NC}"
echo -e "${GREEN}[+] Dashboard disponible en http://192.168.4.1:5000${NC}"

# Mantener el script en ejecución
while true; do
    sleep 1
done