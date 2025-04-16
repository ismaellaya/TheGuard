#!/bin/bash

# Configuración
REPORT_DIR="/var/log/theguard/suricata/reports"
EVE_LOG="/var/log/theguard/suricata/eve.json"
REPORT_FILE="${REPORT_DIR}/suricata_report_$(date +%Y%m%d).txt"
LAST_24H=$(date -d '24 hours ago' +%s)

# Crear directorio de reportes si no existe
mkdir -p "${REPORT_DIR}"

# Función para formatear números grandes
format_number() {
    printf "%'d" $1
}

# Iniciar reporte
{
    echo "=== Reporte de Suricata $(date '+%Y-%m-%d %H:%M:%S') ==="
    echo "Periodo: Últimas 24 horas"
    echo "----------------------------------------"
    
    # Estadísticas de alertas
    echo -e "\n=== Estadísticas de Alertas ==="
    total_alerts=$(jq -r "select(.timestamp | fromdateiso8601 >= $LAST_24H) | select(.event_type==\"alert\") | .alert.signature_id" "${EVE_LOG}" 2>/dev/null | wc -l)
    echo "Total de alertas: $(format_number ${total_alerts})"
    
    # Top 10 alertas más frecuentes
    echo -e "\n=== Top 10 Alertas más Frecuentes ==="
    jq -r "select(.timestamp | fromdateiso8601 >= $LAST_24H) | select(.event_type==\"alert\") | \"\(.alert.signature) [\(.alert.category)]\"" "${EVE_LOG}" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10 | \
    while read -r count alert; do
        printf "%-6s %s\n" "[$count]" "$alert"
    done
    
    # Top 10 IPs origen
    echo -e "\n=== Top 10 IPs de Origen ==="
    jq -r "select(.timestamp | fromdateiso8601 >= $LAST_24H) | select(.event_type==\"alert\") | .src_ip" "${EVE_LOG}" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10 | \
    while read -r count ip; do
        printf "%-6s %s\n" "[$count]" "$ip"
    done
    
    # Top 10 IPs destino
    echo -e "\n=== Top 10 IPs de Destino ==="
    jq -r "select(.timestamp | fromdateiso8601 >= $LAST_24H) | select(.event_type==\"alert\") | .dest_ip" "${EVE_LOG}" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10 | \
    while read -r count ip; do
        printf "%-6s %s\n" "[$count]" "$ip"
    done
    
    # Estadísticas por protocolo
    echo -e "\n=== Estadísticas por Protocolo ==="
    jq -r "select(.timestamp | fromdateiso8601 >= $LAST_24H) | select(.event_type==\"alert\") | .proto" "${EVE_LOG}" 2>/dev/null | \
    sort | uniq -c | sort -rn | \
    while read -r count proto; do
        printf "%-6s %s\n" "[$count]" "$proto"
    done
    
    # Estadísticas por severidad
    echo -e "\n=== Estadísticas por Severidad ==="
    jq -r "select(.timestamp | fromdateiso8601 >= $LAST_24H) | select(.event_type==\"alert\") | .alert.severity" "${EVE_LOG}" 2>/dev/null | \
    sort | uniq -c | sort -rn | \
    while read -r count severity; do
        printf "%-6s Nivel %s\n" "[$count]" "$severity"
    done
    
    # Estado del servicio
    echo -e "\n=== Estado del Servicio ==="
    if systemctl is-active --quiet suricata; then
        uptime=$(systemctl show suricata --property=ActiveEnterTimestamp | cut -d= -f2)
        echo "Estado: Activo desde $uptime"
    else
        echo "Estado: INACTIVO"
    fi
    
    # Uso de recursos
    echo -e "\n=== Uso de Recursos ==="
    cpu=$(ps aux | grep [s]uricata | awk '{print $3}')
    mem=$(ps aux | grep [s]uricata | awk '{print $4}')
    disk=$(df -h /var/log/theguard/suricata | awk 'NR==2 {print $5}')
    echo "CPU: ${cpu:-0}%"
    echo "Memoria: ${mem:-0}%"
    echo "Disco: ${disk:-N/A}"
    
    echo -e "\n=== Fin del Reporte ==="
} > "${REPORT_FILE}"

# Comprimir reportes antiguos (más de 7 días)
find "${REPORT_DIR}" -name "suricata_report_*.txt" -mtime +7 -exec gzip {} \;

# Eliminar reportes muy antiguos (más de 30 días)
find "${REPORT_DIR}" -name "suricata_report_*.txt.gz" -mtime +30 -delete

# Enviar el reporte por correo si está configurado
if [ -x /usr/bin/mail ] && [ -n "${REPORT_EMAIL}" ]; then
    cat "${REPORT_FILE}" | mail -s "Reporte diario de Suricata $(date +%Y-%m-%d)" "${REPORT_EMAIL}"
fi