#!/bin/bash

# Log de instalación
LOG_FILE="/var/log/theguard_snort_setup.log"
exec 1> >(tee -a "$LOG_FILE") 2>&1

echo "[+] Iniciando instalación de Snort $(date)"

# Actualizar el sistema
echo "[+] Actualizando el sistema..."
apt update && apt upgrade -y

# Instalar dependencias necesarias
echo "[+] Instalando dependencias..."
apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev \
    bison flex zlib1g-dev liblzma-dev openssl libssl-dev snort

# Crear directorios necesarios
echo "[+] Configurando directorios..."
mkdir -p /var/log/snort
mkdir -p /etc/snort/rules
chmod -R 750 /var/log/snort

# Copiar archivos de configuración
echo "[+] Copiando archivos de configuración..."
cp config/snort/snort.conf /etc/snort/
cp config/snort/local.rules /etc/snort/rules/

# Configurar la red local
echo "[+] Configurando red local..."
HOME_NET=$(ip route | grep -v default | grep -v 'link' | cut -d' ' -f1 | head -n1)
sed -i "s/var HOME_NET.*/var HOME_NET $HOME_NET/" /etc/snort/snort.conf

# Configurar interfaz de red
IFACE=$(ip -o -4 route show to default | awk '{print $5}')
echo "[+] Configurando interfaz $IFACE..."

# Verificar la configuración
echo "[+] Verificando configuración de Snort..."
snort -T -c /etc/snort/snort.conf -i $IFACE

# Crear servicio systemd para Snort
echo "[+] Creando servicio systemd..."
cat > /etc/systemd/system/snort.service << EOF
[Unit]
Description=Snort NIDS Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i $IFACE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Recargar servicios systemd
systemctl daemon-reload

# Habilitar e iniciar Snort
echo "[+] Habilitando e iniciando servicio Snort..."
systemctl enable snort
systemctl start snort

echo "[+] Instalación completada. Verificar el archivo de log en $LOG_FILE para detalles."