#!/bin/bash

ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEM=80
ALERT_INTERVAL=300  # 5 minutos

while true; do
    # Monitorear CPU y Memoria
    CPU=$(ps aux | grep [s]uricata | awk '{print $3}')
    MEM=$(ps aux | grep [s]uricata | awk '{print $4}')
    
    # Monitorear uso de disco
    DISK_USAGE=$(df /var/log/theguard/suricata | awk 'NR==2 {print $5}' | sed 's/%//')
    
    # Verificar rendimiento y generar alertas
    if (( $(echo "${CPU:-0} > ${ALERT_THRESHOLD_CPU}" | bc -l) )); then
        logger -t suricata-monitor "ALERTA: Alto uso de CPU: ${CPU}%"
    fi
    
    if (( $(echo "${MEM:-0} > ${ALERT_THRESHOLD_MEM}" | bc -l) )); then
        logger -t suricata-monitor "ALERTA: Alto uso de memoria: ${MEM}%"
    fi
    
    if [ "${DISK_USAGE:-0}" -gt 90 ]; then
        logger -t suricata-monitor "ALERTA: Alto uso de disco: ${DISK_USAGE}%"
    fi
    
    # Verificar estado del servicio
    if ! systemctl is-active --quiet suricata; then
        logger -t suricata-monitor "CRÍTICO: Servicio Suricata caído, intentando reiniciar..."
        systemctl restart suricata
    fi
    
    # Verificar archivos de reglas
    if [ ! -d "/etc/suricata/rules/custom" ]; then
        logger -t suricata-monitor "ERROR: Directorio de reglas personalizadas no encontrado"
    fi
    
    # Verificar permisos de directorios críticos
    check_permissions() {
        local dir=$1
        local expected_owner=$2
        local expected_perms=$3
        
        if [ -d "$dir" ]; then
            actual_owner=$(stat -c '%U:%G' "$dir")
            actual_perms=$(stat -c '%a' "$dir")
            
            if [ "$actual_owner" != "$expected_owner" ]; then
                logger -t suricata-monitor "ERROR: Permisos incorrectos en $dir - propietario actual: $actual_owner, esperado: $expected_owner"
            fi
            
            if [ "$actual_perms" != "$expected_perms" ]; then
                logger -t suricata-monitor "ERROR: Permisos incorrectos en $dir - permisos actuales: $actual_perms, esperados: $expected_perms"
            fi
        fi
    }
    
    check_permissions "/var/log/theguard/suricata" "suricata:suricata" "750"
    check_permissions "/etc/suricata/rules" "suricata:suricata" "750"
    
    sleep ${ALERT_INTERVAL}
done