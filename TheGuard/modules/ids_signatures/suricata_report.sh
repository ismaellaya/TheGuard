#!/bin/bash

# Configuración
REPORT_DIR="/var/log/theguard/suricata/reports"
HTML_REPORT="${REPORT_DIR}/report_$(date +%Y%m%d).html"
mkdir -p "${REPORT_DIR}"

# Función para obtener estadísticas
get_stats() {
    local period=$1
    local log_file="/var/log/theguard/suricata/suricata.log"
    
    # Total de alertas
    local total_alerts=$(grep -c "Classification: " ${log_file})
    
    # Alertas por severidad
    local high_sev=$(grep "Priority: 1" ${log_file} | wc -l)
    local med_sev=$(grep "Priority: 2" ${log_file} | wc -l)
    local low_sev=$(grep "Priority: 3" ${log_file} | wc -l)
    
    # Top 10 alertas más frecuentes
    local top_alerts=$(grep "Classification: " ${log_file} | sort | uniq -c | sort -nr | head -n 10)
    
    # Top 10 IPs origen
    local top_src_ips=$(grep "Classification: " ${log_file} | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | head -n 10)
    
    # Uso de recursos
    local cpu_usage=$(ps aux | grep suricata | grep -v grep | awk '{print $3}')
    local mem_usage=$(ps aux | grep suricata | grep -v grep | awk '{print $4}')
    local disk_usage=$(df -h /var/log/theguard/suricata | awk 'NR==2 {print $5}')
    
    # Generar reporte HTML
    cat > "${HTML_REPORT}" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Reporte de Suricata - $(date +%Y-%m-%d)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .high { color: red; }
        .medium { color: orange; }
        .low { color: green; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Reporte de Suricata - $(date +%Y-%m-%d)</h1>
        
        <div class="section">
            <h2>Resumen de Alertas</h2>
            <p>Total de alertas: <strong>${total_alerts}</strong></p>
            <p>Severidad alta: <span class="high">${high_sev}</span></p>
            <p>Severidad media: <span class="medium">${med_sev}</span></p>
            <p>Severidad baja: <span class="low">${low_sev}</span></p>
        </div>
        
        <div class="section">
            <h2>Estado del Sistema</h2>
            <p>Uso de CPU: ${cpu_usage}%</p>
            <p>Uso de memoria: ${mem_usage}%</p>
            <p>Uso de disco: ${disk_usage}</p>
        </div>
        
        <div class="section">
            <h2>Top 10 Alertas más Frecuentes</h2>
            <pre>${top_alerts}</pre>
        </div>
        
        <div class="section">
            <h2>Top 10 IPs de Origen</h2>
            <pre>${top_src_ips}</pre>
        </div>
        
        <div class="section">
            <h2>Estado del Servicio</h2>
            <p>Estado: $(systemctl is-active suricata)</p>
            <p>Uptime: $(ps -o etime= -p $(pgrep suricata))</p>
        </div>
    </div>
</body>
</html>
EOF

    # También generar versión para correo
    local mail_report="${REPORT_DIR}/report_$(date +%Y%m%d).txt"
    cat > "${mail_report}" << EOF
Reporte de Suricata - $(date +%Y-%m-%d)

RESUMEN DE ALERTAS
-----------------
Total de alertas: ${total_alerts}
Severidad alta: ${high_sev}
Severidad media: ${med_sev}
Severidad baja: ${low_sev}

ESTADO DEL SISTEMA
-----------------
CPU: ${cpu_usage}%
Memoria: ${mem_usage}%
Disco: ${disk_usage}

TOP 10 ALERTAS
-------------
${top_alerts}

TOP 10 IPs DE ORIGEN
------------------
${top_src_ips}

ESTADO DEL SERVICIO
-----------------
Estado: $(systemctl is-active suricata)
Uptime: $(ps -o etime= -p $(pgrep suricata))
EOF
}

# Generar reporte
get_stats "daily"

# Enviar reporte por correo si está configurado
if [ -n "${ALERT_EMAIL}" ]; then
    cat "${REPORT_DIR}/report_$(date +%Y%m%d).txt" | mail -s "Reporte Diario de Suricata - $(date +%Y-%m-%d)" "${ALERT_EMAIL}"
fi

# Mantener solo los últimos 30 reportes
find "${REPORT_DIR}" -type f -mtime +30 -delete