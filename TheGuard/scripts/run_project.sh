#!/bin/bash

# Definir la ruta base del proyecto
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Configurar colores para los mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Función para instalar requisitos
setup_requirements() {
    echo -e "${YELLOW}[*] Instalando requisitos del sistema...${NC}"
    
    # Instalar requisitos del sistema
    apt-get update
    apt-get install -y \
        build-essential python3-dev libssl-dev libffi-dev \
        libnetfilter-queue-dev libnfnetlink-dev \
        python3-pip python3-venv curl \
        hostapd dnsmasq iptables iptables-persistent \
        suricata || exit 1

    # Desinstalar cualquier Rust viejo de apt
    apt-get remove -y rustc cargo || true

    # Instalar rustup si no existe
    if ! command -v rustup >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Instalando Rust toolchain vía rustup...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    fi

    # Asegurar que rustup y rustc están en el PATH
    export PATH="$HOME/.cargo/bin:$PATH"
    rustup default stable

    # Crear virtualenv si no existe
    if [ ! -d "${BASE_DIR}/venv" ]; then
        echo -e "${YELLOW}[*] Creando entorno virtual...${NC}"
        python3 -m venv "${BASE_DIR}/venv"
    fi

    VENV_PIP="${BASE_DIR}/venv/bin/pip"
    VENV_PYTHON="${BASE_DIR}/venv/bin/python3"

    echo -e "${YELLOW}[*] Actualizando pip, setuptools y wheel…${NC}"
    $VENV_PIP install --upgrade pip setuptools wheel

    echo -e "${YELLOW}[*] Instalando dependencias Python…${NC}"
    $VENV_PIP install -r "${BASE_DIR}/requirements.txt"

    echo -e "${GREEN}[+] Requirements instalados correctamente${NC}"
}

# Función para crear y configurar directorios
setup_directories() {
    echo -e "${YELLOW}[*] Creando estructura de directorios...${NC}"
    
    mkdir -p "${BASE_DIR}/logs"
    mkdir -p /var/log/theguard/suricata
    mkdir -p /etc/suricata/rules
    mkdir -p /var/lib/suricata/backup
    mkdir -p "${BASE_DIR}/modules/ids_signatures/rules"
    mkdir -p "${BASE_DIR}/modules/anomaly_analysis/model/trained_models"
    chmod -R 755 "${BASE_DIR}/logs" /var/log/theguard /etc/suricata/rules
    chown -R root:root "${BASE_DIR}/logs" /var/log/theguard /etc/suricata/rules
    
    mkdir -p /tmp/theguard
    chmod 777 /tmp/theguard
    
    echo -e "${GREEN}[+] Directorios creados y configurados correctamente${NC}"
}

# Función para configurar Access Point
setup_ap() {
    echo -e "${YELLOW}[*] Configurando modo Access Point...${NC}"
    
    update-alternatives --set iptables /usr/sbin/iptables-legacy
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
    systemctl stop hostapd dnsmasq
    rfkill unblock wlan

    cat > /etc/dhcpcd.conf << EOF
interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
EOF

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

    sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

    cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
EOF

    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p

    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables.ipv4.nat

    systemctl unmask hostapd
    systemctl enable hostapd dnsmasq
    systemctl start hostapd dnsmasq

    echo -e "${GREEN}[+] Access Point configurado${NC}"
}

# Función para instalar y arrancar Suricata
setup_suricata() {
    if systemctl is-active --quiet suricata; then
        echo -e "${YELLOW}[*] Suricata ya está en ejecución${NC}"
        return
    fi

    systemctl unmask suricata
    systemctl enable suricata
    systemctl start suricata

    if ! systemctl is-active --quiet suricata; then
        echo -e "${RED}[!] Error al iniciar Suricata${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Suricata instalado y en ejecución${NC}"
}

# Inicio del script
echo -e "${GREEN}[+] Iniciando TheGuard...${NC}"
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi

setup_requirements
setup_directories
setup_ap
setup_suricata

echo -e "${YELLOW}[*] Instalando configuraciones personalizadas de Suricata...${NC}"
cp "${BASE_DIR}/modules/ids_signatures/rules/et_rules/emerging.rules/rules/"*.config /etc/suricata/rules/
cp "${BASE_DIR}/config/suricata/suricata.yaml" /etc/suricata/
cp "${BASE_DIR}/modules/ids_signatures/rules/custom_rules.rules" /etc/suricata/rules/

echo -e "${YELLOW}[*] Actualizando reglas de Suricata...${NC}"
suricata-update
systemctl restart suricata

echo -e "${YELLOW}[*] Iniciando módulos…${NC}"
VENV_PYTHON="${BASE_DIR}/venv/bin/python3"
PYTHONPATH="${BASE_DIR}"

# Procesador de alertas IDS
$VENV_PYTHON -c "from modules.ids_signatures import get_ids_processor; get_ids_processor().start_monitoring()" &
echo $! > /var/run/theguard_alert_monitor.pid

# Análisis de Anomalías
$VENV_PYTHON -c "from modules.anomaly_analysis import AnomalyModule; AnomalyModule().start()" &
echo $! > /var/run/theguard_anomaly.pid

# DPI
$VENV_PYTHON -c "from modules.dpi import DPIModule; DPIModule().start()" &
echo $! > /var/run/theguard_dpi.pid

# IP Monitoring
$VENV_PYTHON -c "from modules.ip_monitoring import IPMonitoringModule; IPMonitoringModule().start()" &
echo $! > /var/run/theguard_ip_monitoring.pid

# Dashboard
bash "${BASE_DIR}/scripts/start_dashboard.sh" &
echo $! > /var/run/theguard_dashboard.pid

# Función de limpieza
cleanup() {
    echo -e "${YELLOW}[*] Deteniendo servicios...${NC}"
    for pid_file in /var/run/theguard_*.pid; do
        [ -f "$pid_file" ] && kill "$(cat "$pid_file")" && rm "$pid_file"
    done
    systemctl stop suricata hostapd dnsmasq
    echo -e "${GREEN}[+] Todo detenido correctamente${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

echo -e "${GREEN}[+] TheGuard iniciado correctamente${NC}"
echo -e "${GREEN}[+] Dashboard en http://192.168.4.1:5000${NC}"

while true; do sleep 1; done
