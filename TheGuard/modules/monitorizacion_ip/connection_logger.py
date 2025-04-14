import sqlite3
import logging
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

class ConnectionLogger:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Configurar logging
        self.logger = logging.getLogger('monitorizacion_ip.connection_logger')
        
        # Inicializar base de datos
        self.db_path = 'data/connections.db'
        self._init_database()
    
    def _init_database(self):
        """Inicializa la base de datos SQLite para almacenar conexiones."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabla para estadísticas de conexión
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_stats (
                    ip TEXT,
                    timestamp DATETIME,
                    packets INTEGER,
                    bytes INTEGER,
                    ports TEXT,
                    protocols TEXT,
                    reputation INTEGER,
                    PRIMARY KEY (ip, timestamp)
                )
                """)
                
                # Tabla para alertas
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    ip TEXT,
                    alert_type TEXT,
                    details TEXT,
                    severity TEXT
                )
                """)
                
                # Índices para optimizar consultas
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip ON connection_stats(ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON connection_stats(timestamp)")
                
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error inicializando base de datos: {str(e)}")
            raise
    
    def log_connection(self, ip: str, stats: Dict):
        """Registra estadísticas de conexión para una IP."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                INSERT INTO connection_stats (
                    ip, timestamp, packets, bytes, ports, protocols, reputation
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    datetime.now().isoformat(),
                    stats['packets'],
                    stats['bytes'],
                    json.dumps(list(stats['ports'])),
                    json.dumps(stats.get('protocols', [])),
                    stats.get('reputation')
                ))
                
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error registrando conexión: {str(e)}")
    
    def log_alert(self, alert: Dict):
        """Registra una alerta relacionada con una IP."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                INSERT INTO alerts (
                    timestamp, ip, alert_type, details, severity
                ) VALUES (?, ?, ?, ?, ?)
                """, (
                    alert['timestamp'],
                    alert['ip'],
                    alert['type'],
                    json.dumps(alert['details']),
                    alert.get('severity', 'warning')
                ))
                
                conn.commit()
                
        except sqlite3.Error as e:
            self.logger.error(f"Error registrando alerta: {str(e)}")
    
    def get_ip_history(self, ip: str, hours: int = 24) -> List[Dict]:
        """Obtiene el historial de conexiones de una IP."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                since = (datetime.now() - timedelta(hours=hours)).isoformat()
                
                cursor.execute("""
                SELECT * FROM connection_stats 
                WHERE ip = ? AND timestamp > ?
                ORDER BY timestamp DESC
                """, (ip, since))
                
                return [{
                    'timestamp': row['timestamp'],
                    'packets': row['packets'],
                    'bytes': row['bytes'],
                    'ports': json.loads(row['ports']),
                    'protocols': json.loads(row['protocols']),
                    'reputation': row['reputation']
                } for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.error(f"Error obteniendo historial de IP: {str(e)}")
            return []
    
    def get_ip_alerts(self, ip: str, limit: int = 100) -> List[Dict]:
        """Obtiene las alertas relacionadas con una IP."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                SELECT * FROM alerts 
                WHERE ip = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """, (ip, limit))
                
                return [{
                    'timestamp': row['timestamp'],
                    'type': row['alert_type'],
                    'details': json.loads(row['details']),
                    'severity': row['severity']
                } for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            self.logger.error(f"Error obteniendo alertas de IP: {str(e)}")
            return []
    
    def get_statistics(self, hours: int = 24) -> Dict:
        """Obtiene estadísticas generales de conexiones."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                since = (datetime.now() - timedelta(hours=hours)).isoformat()
                
                # Total de IPs únicas
                cursor.execute("""
                SELECT COUNT(DISTINCT ip) FROM connection_stats 
                WHERE timestamp > ?
                """, (since,))
                unique_ips = cursor.fetchone()[0]
                
                # Total de paquetes y bytes
                cursor.execute("""
                SELECT SUM(packets), SUM(bytes) FROM connection_stats 
                WHERE timestamp > ?
                """, (since,))
                total_packets, total_bytes = cursor.fetchone()
                
                # IPs con más tráfico
                cursor.execute("""
                SELECT ip, SUM(packets) as total_packets, SUM(bytes) as total_bytes,
                       MAX(reputation) as last_reputation
                FROM connection_stats 
                WHERE timestamp > ?
                GROUP BY ip
                ORDER BY total_packets DESC
                LIMIT 10
                """, (since,))
                
                top_ips = [{
                    'ip': row[0],
                    'packets': row[1],
                    'bytes': row[2],
                    'reputation': row[3]
                } for row in cursor.fetchall()]
                
                return {
                    'period_hours': hours,
                    'unique_ips': unique_ips,
                    'total_packets': total_packets or 0,
                    'total_bytes': total_bytes or 0,
                    'top_ips': top_ips
                }
                
        except sqlite3.Error as e:
            self.logger.error(f"Error obteniendo estadísticas: {str(e)}")
            return {
                'period_hours': hours,
                'unique_ips': 0,
                'total_packets': 0,
                'total_bytes': 0,
                'top_ips': []
            }
    
    def cleanup_old_data(self, days: int = 30):
        """Elimina datos antiguos de la base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cutoff = (datetime.now() - timedelta(days=days)).isoformat()
                
                cursor.execute("DELETE FROM connection_stats WHERE timestamp < ?", (cutoff,))
                cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
                
                conn.commit()
                
            self.logger.info(f"Datos anteriores a {cutoff} eliminados")
            
        except sqlite3.Error as e:
            self.logger.error(f"Error limpiando datos antiguos: {str(e)}")