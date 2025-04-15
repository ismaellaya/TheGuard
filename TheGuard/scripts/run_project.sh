#!/bin/bash

# Configurar colores para los mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[+] Iniciando TheGuard...${NC}"

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Este script debe ejecutarse como root${NC}"
    exit 1
fi

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
    echo -e "${YELLOW}[*] Configurando Suricata...${NC}"
    
    if ! command -v suricata &> /dev/null; then
        echo -e "${YELLOW}[*] Instalando Suricata...${NC}"
        bash modules/ids_signatures/suricata_setup.sh
    fi
    
    # Verificar que Suricata está funcionando correctamente
    if ! systemctl is-active --quiet suricata; then
        echo -e "${RED}[!] Error: Suricata no está en ejecución${NC}"
        exit 1
    fi
}

# Crear directorios necesarios
mkdir -p /var/log/theguard
mkdir -p /var/log/suricata

# Configurar AP
setup_ap

# Configurar Suricata
setup_suricata

# Actualizar reglas de Suricata
echo -e "${YELLOW}[*] Actualizando reglas de Suricata...${NC}"
suricata-update

# Copiar reglas personalizadas
echo -e "${YELLOW}[*] Instalando reglas personalizadas...${NC}"
cp modules/ids_signatures/rules/custom_rules.rules /etc/suricata/rules/
systemctl restart suricata

# Iniciar el dashboard
echo -e "${YELLOW}[*] Iniciando dashboard...${NC}"
bash scripts/start_dashboard.sh &

# Iniciar el procesador de alertas de Suricata
echo -e "${YELLOW}[*] Iniciando sistema de monitoreo de alertas...${NC}"
python3 -c "from modules.ids_signatures import get_ids_processor; get_ids_processor().start_monitoring()" &

# Registrar PIDs para limpieza al salir
echo $! > /var/run/theguard_alert_monitor.pid

# Función de limpieza
cleanup() {
    echo -e "${YELLOW}[*] Deteniendo servicios...${NC}"
    # Detener monitor de alertas
    if [ -f /var/run/theguard_alert_monitor.pid]; then
        kill $(cat /var/run/theguard_alert_monitor.pid)
        rm /var/run/theguard_alert_monitor.pid
    fi
    # Detener Suricata
    systemctl stop suricata
}

# Registrar función de limpieza para señales de terminación
trap cleanup SIGINT SIGTERM

echo -e "${GREEN}[+] TheGuard iniciado correctamente${NC}"
echo -e "${GREEN}[+] Dashboard disponible en http://192.168.4.1:5000${NC}"

# Mantener el script en ejecución
while true; do
    sleep 1
done