from flask import Flask, render_template, jsonify
import yaml
import os
from modules.ids_firmas import get_integration

app = Flask(__name__)

# Cargar configuración
with open('config/global_config.yaml', 'r') as f:
    config = yaml.safe_load(f)
    
app.config['SECRET_KEY'] = config['dashboard']['secret_key']

# Obtener instancia del sistema de integración
alert_integration = get_integration()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/alerts')
def get_alerts():
    """Endpoint para obtener alertas desde diferentes módulos."""
    try:
        # Obtener estadísticas de alertas del sistema de integración
        stats = alert_integration.get_statistics()
        
        # Formatear datos para el frontend
        alert_data = {
            'ids_firmas': stats['alert_counts'].get('sql_injection', 0) + 
                         stats['alert_counts'].get('xss', 0) +
                         stats['alert_counts'].get('command_injection', 0),
            'anomalias': stats['alert_counts'].get('anomaly', 0),
            'dpi': stats['alert_counts'].get('malware', 0) +
                   stats['alert_counts'].get('dns_anomaly', 0),
            'monitorizacion_ip': stats['alert_counts'].get('port_scan', 0) +
                                stats['alert_counts'].get('brute_force', 0),
            'recent': [{
                'type': alert['type'],
                'message': alert['message'],
                'timestamp': alert['timestamp'],
                'severity': alert['severity'],
                'module': 'IDS'
            } for alert in stats.get('recent_alerts', [])]
        }
        
        return jsonify(alert_data)
    except Exception as e:
        app.logger.error(f"Error obteniendo alertas: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/stats')
def get_stats():
    """Endpoint para obtener estadísticas generales."""
    try:
        stats = alert_integration.get_statistics()
        
        response = {
            'total_alerts': stats['total_alerts'],
            'active_threats': sum(1 for alert in stats.get('recent_alerts', [])
                                if alert['severity'] == 'danger'),
            'monitored_ips': len(set(alert['source_ip'] 
                                   for alert in stats.get('recent_alerts', [])
                                   if 'source_ip' in alert)),
            'suspicious_ips': [
                {
                    'address': alert.get('source_ip', 'Unknown'),
                    'alert_count': stats['alert_counts'].get(alert['type'], 0),
                    'first_seen': min(a['timestamp'] 
                                    for a in stats.get('recent_alerts', [])
                                    if a.get('source_ip') == alert.get('source_ip')),
                    'last_seen': max(a['timestamp']
                                   for a in stats.get('recent_alerts', [])
                                   if a.get('source_ip') == alert.get('source_ip')),
                    'reputation': alert.get('reputation', 0)
                }
                for alert in stats.get('recent_alerts', [])
                if 'source_ip' in alert
            ]
        }
        
        return jsonify(response)
    except Exception as e:
        app.logger.error(f"Error obteniendo estadísticas: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == '__main__':
    app.run(
        host=config['dashboard']['host'],
        port=config['dashboard']['port'],
        debug=config['dashboard']['debug']
    )