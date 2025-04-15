import logging
import yaml
from typing import Dict, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from .connection_logger import ConnectionLogger
from .abuse_ipdb_integration import AbuseIPDBClient

class IPTracker:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Configurar logging
        self.logger = logging.getLogger('ip_monitoring.ip_tracker')
        
        # Estructuras de datos para seguimiento
        self.connections: Dict[str, Dict] = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None,
            'ports': set(),
            'reputation': None,
            'alerts': 0
        })
        
        # Inicializar componentes
        self.connection_logger = ConnectionLogger()
        self.abuse_ipdb = AbuseIPDBClient()
        
        # Umbrales de detección
        self.thresholds = {
            'packets_per_minute': 1000,  # Umbral de paquetes por minuto
            'ports_scanned': 20,         # Número de puertos únicos para considerar escaneo
            'max_bytes_per_minute': 1000000,  # 1MB por minuto
            'reputation_threshold': 50,   # Score de reputación mínimo aceptable
            'alert_threshold': 5         # Número de alertas antes de considerar IP maliciosa
        }
    
    def track_connection(self, connection_data: Dict) -> Optional[Dict]:
        """Procesa y analiza una nueva conexión."""
        try:
            source_ip = connection_data['source_ip']
            dest_ip = connection_data['dest_ip']
            now = datetime.now()
            
            # Actualizar estadísticas para IP origen
            self._update_ip_stats(source_ip, connection_data, now)
            
            # Verificar comportamiento sospechoso
            alerts = []
            
            # Verificar tasa de paquetes
            packets_per_minute = self._calculate_rate(
                self.connections[source_ip]['packets'],
                self.connections[source_ip]['first_seen'],
                now
            )
            if packets_per_minute > self.thresholds['packets_per_minute']:
                alerts.append({
                    'type': 'high_traffic',
                    'detail': f'High packet rate: {packets_per_minute} packets/min'
                })
            
            # Verificar escaneo de puertos
            if len(self.connections[source_ip]['ports']) > self.thresholds['ports_scanned']:
                alerts.append({
                    'type': 'port_scan',
                    'detail': f'Port scanning detected: {len(self.connections[source_ip]["ports"])} ports'
                })
            
            # Verificar tasa de bytes
            bytes_per_minute = self._calculate_rate(
                self.connections[source_ip]['bytes'],
                self.connections[source_ip]['first_seen'],
                now
            )
            if bytes_per_minute > self.thresholds['max_bytes_per_minute']:
                alerts.append({
                    'type': 'bandwidth_abuse',
                    'detail': f'High bandwidth usage: {bytes_per_minute/1000000:.2f} MB/min'
                })
            
            # Verificar reputación si no se ha hecho antes
            if self.connections[source_ip]['reputation'] is None:
                reputation = self.abuse_ipdb.check_ip(source_ip)
                if reputation:
                    self.connections[source_ip]['reputation'] = reputation['abuse_confidence_score']
                    if reputation['abuse_confidence_score'] > self.thresholds['reputation_threshold']:
                        alerts.append({
                            'type': 'bad_reputation',
                            'detail': f'Poor IP reputation: {reputation["abuse_confidence_score"]}'
                        })
            
            # Registrar conexión
            self.connection_logger.log_connection(connection_data)
            
            # Generar alerta si hay comportamiento sospechoso
            if alerts:
                self.connections[source_ip]['alerts'] += 1
                alert = {
                    'timestamp': now.isoformat(),
                    'ip': source_ip,
                    'alerts': alerts,
                    'total_alerts': self.connections[source_ip]['alerts'],
                    'connection_data': connection_data
                }
                
                # Si supera el umbral de alertas, reportar a AbuseIPDB
                if self.connections[source_ip]['alerts'] >= self.thresholds['alert_threshold']:
                    categories = self._determine_abuse_categories(alerts)
                    comment = self._generate_abuse_report(alert)
                    self.abuse_ipdb.report_ip(source_ip, categories, comment)
                
                return alert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error tracking connection: {str(e)}")
            return None
    
    def _update_ip_stats(self, ip: str, connection_data: Dict, timestamp: datetime):
        """Actualiza las estadísticas para una IP."""
        if not self.connections[ip]['first_seen']:
            self.connections[ip]['first_seen'] = timestamp
        
        self.connections[ip]['last_seen'] = timestamp
        self.connections[ip]['packets'] += connection_data.get('packets', 1)
        self.connections[ip]['bytes'] += connection_data.get('bytes', 0)
        if 'dest_port' in connection_data:
            self.connections[ip]['ports'].add(connection_data['dest_port'])
    
    def _calculate_rate(self, value: int, start: datetime, end: datetime) -> float:
        """Calcula la tasa por minuto de un valor."""
        if not start or not end:
            return 0.0
        duration = (end - start).total_seconds() / 60  # convertir a minutos
        return value / max(duration, 0.0167)  # mínimo 1 segundo
    
    def _determine_abuse_categories(self, alerts: list) -> list:
        """Determina las categorías de abuso basadas en las alertas."""
        categories = []
        for alert in alerts:
            if alert['type'] == 'port_scan':
                categories.append(14)  # Port Scan
            elif alert['type'] == 'bandwidth_abuse':
                categories.append(4)   # DDOS
            elif alert['type'] == 'bad_reputation':
                categories.append(21)  # Malicious Host
        return list(set(categories))
    
    def _generate_abuse_report(self, alert: Dict) -> str:
        """Genera un reporte detallado para AbuseIPDB."""
        report = f"Multiple suspicious activities detected from {alert['ip']}:\n"
        for detection in alert['alerts']:
            report += f"- {detection['type']}: {detection['detail']}\n"
        report += f"Total alerts: {alert['total_alerts']}"
        return report
    
    def get_ip_stats(self, ip: str) -> Optional[Dict]:
        """Obtiene las estadísticas completas de una IP."""
        if ip in self.connections:
            return {
                'ip': ip,
                **self.connections[ip],
                'ports': list(self.connections[ip]['ports'])
            }
        return None
    
    def get_suspicious_ips(self) -> list:
        """Retorna lista de IPs con comportamiento sospechoso."""
        suspicious = []
        for ip, data in self.connections.items():
            if data['alerts'] > 0:
                suspicious.append({
                    'ip': ip,
                    'alerts': data['alerts'],
                    'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
                    'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None,
                    'reputation': data['reputation']
                })
        return suspicious