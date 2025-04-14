// Función para actualizar las estadísticas del dashboard
async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('total-alerts').textContent = stats.total_alerts;
        document.getElementById('active-threats').textContent = stats.active_threats;
        document.getElementById('monitored-ips').textContent = stats.monitored_ips;
    } catch (error) {
        console.error('Error al actualizar estadísticas:', error);
    }
}

// Función para inicializar el gráfico de alertas
function initializeAlertsChart() {
    const ctx = document.getElementById('alerts-chart').getContext('2d');
    const alertsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['IDS Firmas', 'Anomalías', 'DPI', 'Monitorización IP'],
            datasets: [{
                label: 'Alertas por Módulo',
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)',
                    'rgba(54, 162, 235, 0.5)',
                    'rgba(255, 206, 86, 0.5)',
                    'rgba(75, 192, 192, 0.5)'
                ],
                borderColor: [
                    'rgb(255, 99, 132)',
                    'rgb(54, 162, 235)',
                    'rgb(255, 206, 86)',
                    'rgb(75, 192, 192)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });

    // Actualizar el gráfico cada minuto
    setInterval(async () => {
        try {
            const response = await fetch('/api/alerts');
            const alerts = await response.json();
            
            // Actualizar datos del gráfico
            alertsChart.data.datasets[0].data = [
                alerts.ids_firmas || 0,
                alerts.anomalias || 0,
                alerts.dpi || 0,
                alerts.monitorizacion_ip || 0
            ];
            alertsChart.update();
            
            // Actualizar lista de alertas recientes
            updateRecentAlerts(alerts.recent || []);
        } catch (error) {
            console.error('Error al actualizar el gráfico:', error);
        }
    }, 60000);
}

// Función para actualizar la lista de alertas recientes
function updateRecentAlerts(alerts) {
    const container = document.getElementById('recent-alerts');
    container.innerHTML = '';
    
    alerts.forEach(alert => {
        const alertElement = document.createElement('div');
        alertElement.className = `list-group-item list-group-item-${alert.severity || 'warning'}`;
        alertElement.innerHTML = `
            <div class="d-flex w-100 justify-content-between">
                <h6 class="mb-1">${alert.type}</h6>
                <small>${new Date(alert.timestamp).toLocaleTimeString()}</small>
            </div>
            <p class="mb-1">${alert.message}</p>
            <small>Módulo: ${alert.module}</small>
        `;
        container.appendChild(alertElement);
    });
}

// Función para actualizar la tabla de IPs sospechosas
async function updateSuspiciousIPs() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        const tbody = document.getElementById('suspicious-ips');
        tbody.innerHTML = '';
        
        (data.suspicious_ips || []).forEach(ip => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${ip.address}</td>
                <td>${ip.alert_count}</td>
                <td>${new Date(ip.first_seen).toLocaleString()}</td>
                <td>${new Date(ip.last_seen).toLocaleString()}</td>
                <td><span class="badge bg-${getReputationBadgeClass(ip.reputation)}">${ip.reputation}</span></td>
                <td>
                    <button class="btn btn-sm btn-warning" onclick="blockIP('${ip.address}')">Bloquear</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Error al actualizar IPs sospechosas:', error);
    }
}

// Función auxiliar para determinar el color del badge de reputación
function getReputationBadgeClass(reputation) {
    if (reputation >= 80) return 'success';
    if (reputation >= 50) return 'warning';
    return 'danger';
}

// Función para bloquear una IP
async function blockIP(ip) {
    try {
        const response = await fetch('/api/block-ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip })
        });
        
        if (response.ok) {
            alert(`IP ${ip} bloqueada exitosamente`);
            updateSuspiciousIPs();
        } else {
            throw new Error('Error al bloquear la IP');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error al intentar bloquear la IP');
    }
}