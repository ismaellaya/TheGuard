#!/bin/bash

# —————————————————————————————————————————————————————————
#              TheGuard: script de arranque
# —————————————————————————————————————————————————————————

# 1) Definir la ruta base del proyecto (un nivel arriba de /scripts/)
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# 2) Colores para resaltar salidas en pantalla
RED='\033[0;31m'     # rojo para errores
GREEN='\033[0;32m'   # verde para confirmaciones
YELLOW='\033[1;33m'  # amarillo para información
NC='\033[0m'         # sin color (reset)

/################################################################################
# Función: setup_requirements
# — Instala las dependencias de sistema y crea/actualiza el virtualenv Python
################################################################################
setup_requirements() {
    echo -e "${YELLOW}[*] Instalando requisitos del sistema...${NC}"
    
    # 3) Dependencias nativas necesarias para compilar paquetes Python con Rust/FFI
    apt-get update
    apt-get install -y \
        build-essential \         # compilador C/C++ y make
        python3-dev \             # cabeceras de Python
        libssl-dev libffi-dev \   # librerías para cryptography, bcrypt, etc.
        cargo rustc \             # toolchain de Rust (necesario para cryptography >=40)
        libnetfilter-queue-dev \  # headers para netfilterqueue
        libnfnetlink-dev \
        python3-pip python3-venv  # pip y módulo venv

    # 4) Crear el entorno virtual si no existe
    if [ ! -d "${BASE_DIR}/venv" ]; then
        echo -e "${YELLOW}[*] Creando entorno virtual...${NC}"
        python3 -m venv "${BASE_DIR}/venv"
    fi
    
    # 5) Atajo a los binarios del venv
    VENV_PIP="${BASE_DIR}/venv/bin/pip"
    VENV_PYTHON="${BASE_DIR}/venv/bin/python3"

    # 6) Asegurar pip, setuptools y wheel actualizados en el venv
    echo -e "${YELLOW}[*] Actualizando pip, setuptools y wheel…${NC}"
    $VENV_PIP install --upgrade pip setuptools wheel

    # 7) Instalar todas las dependencias Python desde requirements.txt
    if [ -f "${BASE_DIR}/requirements.txt" ]; then
        echo -e "${YELLOW}[*] Instalando dependencias Python…${NC}"
        $VENV_PIP install -r "${BASE_DIR}/requirements.txt"
    else
        echo -e "${RED}[!] No se encontró requirements.txt${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Requirements instalados correctamente${NC}"
}

################################################################################
# Función: setup_directories
# — Crea y da permisos a la estructura de carpetas que usa TheGuard
################################################################################
setup_directories() {
    echo -e "${YELLOW}[*] Creando estructura de directorios...${NC}"
    
    # Directorios principales de logs y configuraciones
    mkdir -p "${BASE_DIR}/logs"
    mkdir -p /var/log/theguard/suricata
    mkdir -p /etc/suricata/rules
    mkdir -p /var/lib/suricata/backup
    mkdir -p "${BASE_DIR}/modules/ids_signatures/rules"
    mkdir -p "${BASE_DIR}/modules/anomaly_analysis/model/trained_models"
    
    # Ajustar permisos y propietario
    chown -R root:root /var/log/theguard
    chmod -R 755 /var/log/theguard
    chown -R root:root /etc/suricata
    chmod -R 755 /etc/suricata
    
    # Directorio temporal de TheGuard
    mkdir -p /tmp/theguard
    chmod 777 /tmp/theguard
    
    echo -e "${GREEN}[+] Directorios creados y configurados correctamente${NC}"
}

# Mensaje de inicio
echo -e "${GREEN}[+] Iniciando TheGuard...${NC}"

# 0) Comprobar que ejecutamos como root (necesario para apt, systemctl, iptables…)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi

# 1) Instalación de requisitos
setup_requirements

# 2) Creación de directorios
setup_directories

################################################################################
# Función: setup_ap
# — Configura la Raspberry Pi como punto de acceso Wi-Fi con hostapd & dnsmasq
################################################################################
setup_ap() {
    echo -e "${YELLOW}[*] Configurando modo Access Point...${NC}"
    
    # Instalar herramientas AP
    apt-get update
    apt-get install -y hostapd dnsmasq iptables iptables-persistent

    # Forzar iptables-legacy
    update-alternatives --set iptables /usr/sbin/iptables-legacy
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

    # Detener servicios mientras configuramos
    systemctl stop hostapd
    systemctl stop dnsmasq

    # Desbloquear Wi-Fi si estuviera bloqueada
    rfkill unblock wlan

    # 3) Configurar IP estática en wlan0 vía dhcpcd.conf
    cat > /etc/dhcpcd.conf << EOF
interface wlan0
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
EOF

    # 4) Generar hostapd.conf con SSID y credenciales
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

    # Apuntar el servicio a nuestro hostapd.conf
    sed -i 's|#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
    
    # 5) Configurar DHCP con dnsmasq
    cat > /etc/dnsmasq.conf << EOF
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
EOF

    # 6) Habilitar reenvío de IP y NAT
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables.ipv4.nat

    # 7) Habilitar e iniciar servicios
    systemctl unmask hostapd
    systemctl enable hostapd
    systemctl enable dnsmasq
    systemctl start hostapd
    systemctl start dnsmasq
}

################################################################################
# Función: setup_suricata
# — Instala y arranca Suricata (IDS) si aún no está corriendo
################################################################################
setup_suricata() {
    if systemctl is-active --quiet suricata; then
        echo -e "${YELLOW}[*] Suricata ya está en ejecución${NC}"
        return
    fi

    # Si nunca se instaló/configuró, lanza tu script de setup
    if [ ! -f "/etc/suricata/suricata.yaml" ]; then
        echo -e "${YELLOW}[*] Primera instalación detectada${NC}"
        bash "${BASE_DIR}/modules/ids_signatures/suricata_setup.sh"
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] Error en la instalación inicial de Suricata${NC}"
            exit 1
        fi
    else
        # En posteriores arranques, simplemente inicia Suricata
        systemctl start suricata
    fi

    # Verifica que arrancó correctamente
    if ! systemctl is-active --quiet suricata; then
        echo -e "${RED}[!] Error: No se pudo iniciar Suricata${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Suricata configurado y ejecutando correctamente${NC}"
}

# 3) Configurar AP
setup_ap

# 4) Configurar Suricata
setup_suricata

echo -e "${YELLOW}[*] Instalando configuraciones personalizadas...${NC}"
# Copia tus archivos de reglas y config personalizados a /etc/suricata
cp "${BASE_DIR}/modules/ids_signatures/rules/et_rules/emerging.rules/rules/classification.config" /etc/suricata/rules/
cp "${BASE_DIR}/modules/ids_signatures/rules/et_rules/emerging.rules/rules/reference.config"      /etc/suricata/rules/
cp "${BASE_DIR}/config/suricata/suricata.yaml"                                                        /etc/suricata/

echo -e "${YELLOW}[*] Actualizando reglas de Suricata...${NC}"
suricata-update

cp "${BASE_DIR}/modules/ids_signatures/rules/custom_rules.rules"         /etc/suricata/rules/
cp "${BASE_DIR}/modules/ids_signatures/rules/et_rules/emerging.rules/rules/"*.rules /etc/suricata/rules/

# Reinicia Suricata para aplicar cambios
systemctl restart suricata

################################################################################
# Iniciar módulos propios de TheGuard (IDS, Anomalías, DPI, IP, Dashboard...)
################################################################################

# 5) Procesador de alertas IDS
echo -e "${YELLOW}[*] Iniciando sistema de monitoreo de alertas...${NC}"
PYTHONPATH="${BASE_DIR}" "$VENV_PYTHON" -c "from modules.ids_signatures import get_ids_processor; get_ids_processor().start_monitoring()" &
echo $! > /var/run/theguard_alert_monitor.pid

# 6) Análisis de anomalías
echo -e "${YELLOW}[*] Iniciando Módulo 2 (Análisis de Anomalías)...${NC}"
PYTHONPATH="${BASE_DIR}" "$VENV_PYTHON" -c "from modules.anomaly_analysis import AnomalyModule; AnomalyModule().start()" &
echo $! > /var/run/theguard_anomaly.pid

# 7) DPI
echo -e "${YELLOW}[*] Iniciando Módulo 3 (DPI)...${NC}"
PYTHONPATH="${BASE_DIR}" "$VENV_PYTHON" -c "from modules.dpi import DPIModule; DPIModule().start()" &
echo $! > /var/run/theguard_dpi.pid

# 8) IP Monitoring
echo -e "${YELLOW}[*] Iniciando Módulo 4 (IP Monitoring)...${NC}"
PYTHONPATH="${BASE_DIR}" "$VENV_PYTHON" -c "from modules.ip_monitoring import IPMonitoringModule; IPMonitoringModule().start()" &
echo $! > /var/run/theguard_ip_monitoring.pid

# 9) Dashboard (Flask u otro)
echo -e "${YELLOW}[*] Iniciando Dashboard...${NC}"
bash "${BASE_DIR}/scripts/start_dashboard.sh" &
echo $! > /var/run/theguard_dashboard.pid

################################################################################
# Función de limpieza: mata todos los pids y servicios al recibir SIGINT/SIGTERM
################################################################################
cleanup() {
    echo -e "${YELLOW}[*] Deteniendo servicios...${NC}"
    
    # Matar todos los procesos propios
    for pid_file in /var/run/theguard_*.pid; do
        [ -f "$pid_file" ] && kill "$(cat "$pid_file)" && rm "$pid_file"
    done
    
    # Parar Suricata y AP
    systemctl stop suricata
    systemctl stop hostapd
    systemctl stop dnsmasq
    
    echo -e "${GREEN}[+] Todos los módulos detenidos correctamente${NC}"
    exit 0
}

# Registrar trap para CTRL+C u otras señales de terminación
trap cleanup SIGINT SIGTERM

echo -e "${GREEN}[+] TheGuard iniciado correctamente${NC}"
echo -e "${GREEN}[+] Dashboard disponible en http://192.168.4.1:5000${NC}"

# Bucle infinito para mantener vivo el script hasta CTRL+C
while true; do
    sleep 1
done
