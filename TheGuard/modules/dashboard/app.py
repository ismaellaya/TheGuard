from flask import Flask, render_template, jsonify
import yaml
import os
from modules.ids_signatures import get_integration

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
            'ids_signatures': stats['alert_counts'].get('sql_injection', 0) + 
                         stats['alert_counts'].get('xss', 0) +
                         stats['alert_counts'].get('command_injection', 0),
            'anomalias': stats['alert_counts'].get('anomaly', 0),
            'dpi': stats['alert_counts'].get('malware', 0) +
                   stats['alert_counts'].get('dns_anomaly', 0),
            'ip_monitoring': stats['alert_counts'].get('port_scan', 0) +
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
        stats = alert_integration.get_stats()
        return jsonify({
            'ids_signatures': stats['alert_counts'].get('sql_injection', 0) + 
                          stats['alert_counts'].get('xss', 0) +
                          stats['alert_counts'].get('path_traversal', 0),
            'dpi': stats['alert_counts'].get('malware', 0) +
                 stats['alert_counts'].get('dns_anomaly', 0),
            'ip_monitoring': stats['alert_counts'].get('port_scan', 0) +
                         stats['alert_counts'].get('brute_force', 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(
        host=config['dashboard']['host'],
        port=config['dashboard']['port'],
        debug=config['dashboard']['debug']
    )