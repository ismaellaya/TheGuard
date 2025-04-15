import sqlite3
import logging
import yaml
from typing import Dict, List, Optional
from datetime import datetime, timedelta

class ConnectionLogger:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Configurar logging
        self.logger = logging.getLogger('ip_monitoring.connection_logger')
        
        # Inicializar base de datos
        self.db_path = 'data/connections.db'
        self._init_database()
    
    def _init_database(self):
        """Inicializa la base de datos SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tabla de conexiones
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS connections (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_ip TEXT NOT NULL,
                        dest_ip TEXT NOT NULL,
                        source_port INTEGER,
                        dest_port INTEGER,
                        protocol TEXT,
                        bytes_sent INTEGER,
                        bytes_received INTEGER,
                        timestamp DATETIME,
                        duration REAL
                    )
                ''')
                
                # Tabla de estadísticas por IP
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_stats (
                        ip TEXT PRIMARY KEY,
                        total_connections INTEGER,
                        total_bytes INTEGER,
                        first_seen DATETIME,
                        last_seen DATETIME,
                        reputation_score REAL
                    )
                ''')
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error initializing database: {str(e)}")
            raise
    
    def log_connection(self, connection_data: Dict):
        """Registra una nueva conexión en la base de datos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insertar conexión
                cursor.execute('''
                    INSERT INTO connections (
                        source_ip, dest_ip, source_port, dest_port,
                        protocol, bytes_sent, bytes_received,
                        timestamp, duration
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    connection_data['source_ip'],
                    connection_data['dest_ip'],
                    connection_data.get('source_port'),
                    connection_data.get('dest_port'),
                    connection_data.get('protocol'),
                    connection_data.get('bytes_sent', 0),
                    connection_data.get('bytes_received', 0),
                    datetime.now().isoformat(),
                    connection_data.get('duration', 0)
                ))
                
                # Actualizar estadísticas para ambas IPs
                self._update_ip_stats(cursor, connection_data['source_ip'])
                self._update_ip_stats(cursor, connection_data['dest_ip'])
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error logging connection: {str(e)}")
    
    def _update_ip_stats(self, cursor, ip: str):
        """Actualiza las estadísticas para una IP."""
        try:
            now = datetime.now()
            cursor.execute('''
                INSERT OR REPLACE INTO ip_stats (
                    ip, total_connections, total_bytes,
                    first_seen, last_seen, reputation_score
                )
                VALUES (
                    ?,
                    COALESCE((SELECT total_connections + 1 FROM ip_stats WHERE ip = ?), 1),
                    COALESCE((SELECT total_bytes FROM ip_stats WHERE ip = ?), 0),
                    COALESCE((SELECT first_seen FROM ip_stats WHERE ip = ?), ?),
                    ?,
                    COALESCE((SELECT reputation_score FROM ip_stats WHERE ip = ?), 100)
                )
            ''', (ip, ip, ip, ip, now.isoformat(), now.isoformat(), ip))
        except Exception as e:
            self.logger.error(f"Error updating IP stats for {ip}: {str(e)}")
    
    def get_ip_stats(self, ip: str) -> Optional[Dict]:
        """Obtiene las estadísticas de una IP específica."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM ip_stats WHERE ip = ?', (ip,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'ip': row[0],
                        'total_connections': row[1],
                        'total_bytes': row[2],
                        'first_seen': row[3],
                        'last_seen': row[4],
                        'reputation_score': row[5]
                    }
                return None
        except Exception as e:
            self.logger.error(f"Error getting IP stats for {ip}: {str(e)}")
            return None
    
    def get_recent_connections(self, minutes: int = 5) -> List[Dict]:
        """Obtiene las conexiones recientes en los últimos X minutos."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                since = (datetime.now() - timedelta(minutes=minutes)).isoformat()
                
                cursor.execute('''
                    SELECT * FROM connections 
                    WHERE timestamp > ? 
                    ORDER BY timestamp DESC
                ''', (since,))
                
                connections = []
                for row in cursor.fetchall():
                    connections.append({
                        'id': row[0],
                        'source_ip': row[1],
                        'dest_ip': row[2],
                        'source_port': row[3],
                        'dest_port': row[4],
                        'protocol': row[5],
                        'bytes_sent': row[6],
                        'bytes_received': row[7],
                        'timestamp': row[8],
                        'duration': row[9]
                    })
                return connections
        except Exception as e:
            self.logger.error(f"Error getting recent connections: {str(e)}")
            return []
    
    def update_ip_reputation(self, ip: str, score: float):
        """Actualiza el score de reputación de una IP."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE ip_stats 
                    SET reputation_score = ? 
                    WHERE ip = ?
                ''', (score, ip))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error updating reputation for {ip}: {str(e)}")