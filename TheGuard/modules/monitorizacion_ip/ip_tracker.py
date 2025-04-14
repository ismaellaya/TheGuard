import time
import yaml
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from scapy.all import sniff, IP
from .abuse_ipdb_integration import check_ip_reputation

class IPTracker:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Configurar logging
        logging.basicConfig(
            filename=self.config['logging']['file'],
            level=getattr(logging, self.config['logging']['level']),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('monitorizacion_ip.ip_tracker')
        
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
        
        # Umbrales de detección
        self.thresholds = {
            'packets_per_minute': 1000,  # Umbral de paquetes por minuto
            'connections_per_minute': 50,  # Conexiones únicas por minuto
            'reputation_threshold': 50,  # Puntuación mínima aceptable de reputación
        }
        
        # Cache de reputación
        self.reputation_cache: Dict[str, Dict] = {}
        self.cache_timeout = timedelta(hours=1)
    
    def start_monitoring(self):
        """Inicia el monitoreo de tráfico IP."""
        try:
            self.logger.info(f"Iniciando monitoreo en interfaz {self.config['network']['interface']}")
            sniff(
                iface=self.config['network']['interface'],
                filter="ip",
                prn=self.process_packet,
                store=0
            )
        except Exception as e:
            self.logger.error(f"Error al iniciar monitoreo: {str(e)}")
            raise
    
    def process_packet(self, packet):
        """Procesa cada paquete capturado para análisis IP."""
        if IP not in packet:
            return
        
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Actualizar estadísticas para IP origen
            self._update_ip_stats(src_ip, packet)
            
            # Verificar comportamiento sospechoso
            if self._is_suspicious(src_ip):
                self._handle_suspicious_ip(src_ip)
        except Exception as e:
            self.logger.error(f"Error procesando paquete: {str(e)}")
    
    def _update_ip_stats(self, ip: str, packet):
        """Actualiza las estadísticas para una IP."""
        now = datetime.now()
        
        if self.connections[ip]['first_seen'] is None:
            self.connections[ip]['first_seen'] = now
        
        self.connections[ip]['last_seen'] = now
        self.connections[ip]['packets'] += 1
        self.connections[ip]['bytes'] += len(packet)
        
        # Actualizar puertos si es TCP o UDP
        if hasattr(packet, 'sport'):
            self.connections[ip]['ports'].add(packet.sport)
        if hasattr(packet, 'dport'):
            self.connections[ip]['ports'].add(packet.dport)
        
        # Verificar reputación si es necesario
        self._check_reputation_if_needed(ip)
    
    def _is_suspicious(self, ip: str) -> bool:
        """Determina si una IP muestra comportamiento sospechoso."""
        stats = self.connections[ip]
        now = datetime.now()
        
        # Verificar tasa de paquetes
        if stats['last_seen'] and stats['first_seen']:
            duration = (stats['last_seen'] - stats['first_seen']).total_seconds() / 60
            if duration > 0:
                packets_per_minute = stats['packets'] / duration
                if packets_per_minute > self.thresholds['packets_per_minute']:
                    return True
        
        # Verificar reputación
        if stats['reputation'] is not None:
            if stats['reputation'] < self.thresholds['reputation_threshold']:
                return True
        
        # Verificar número de puertos únicos
        if len(stats['ports']) > self.thresholds['connections_per_minute']:
            return True
        
        return False
    
    def _check_reputation_if_needed(self, ip: str):
        """Verifica la reputación de una IP si no está en caché o expiró."""
        now = datetime.now()
        
        if (ip not in self.reputation_cache or 
            now - self.reputation_cache[ip]['timestamp'] > self.cache_timeout):
            
            try:
                reputation = check_ip_reputation(ip)
                self.reputation_cache[ip] = {
                    'score': reputation,
                    'timestamp': now
                }
                self.connections[ip]['reputation'] = reputation
            except Exception as e:
                self.logger.error(f"Error al verificar reputación de {ip}: {str(e)}")
    
    def _handle_suspicious_ip(self, ip: str):
        """Maneja una IP identificada como sospechosa."""
        stats = self.connections[ip]
        stats['alerts'] += 1
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'type': 'suspicious_activity',
            'details': {
                'packets': stats['packets'],
                'ports_accessed': len(stats['ports']),
                'reputation': stats['reputation'],
                'duration': (stats['last_seen'] - stats['first_seen']).total_seconds()
            }
        }
        
        self.logger.warning(f"Actividad sospechosa detectada: {alert}")
        # TODO: Integrar con el dashboard para mostrar la alerta
    
    def get_statistics(self) -> Dict:
        """Retorna estadísticas actuales de monitoreo IP."""
        now = datetime.now()
        active_ips = sum(1 for ip in self.connections 
                        if self.connections[ip]['last_seen'] > now - timedelta(minutes=5))
        
        return {
            'total_ips': len(self.connections),
            'active_ips': active_ips,
            'suspicious_ips': sum(1 for ip in self.connections 
                                if self.connections[ip]['alerts'] > 0),
            'top_talkers': self._get_top_talkers(),
            'recent_alerts': self._get_recent_alerts()
        }
    
    def _get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Retorna las IPs más activas."""
        sorted_ips = sorted(
            self.connections.items(),
            key=lambda x: x[1]['packets'],
            reverse=True
        )[:limit]
        
        return [{
            'ip': ip,
            'packets': stats['packets'],
            'bytes': stats['bytes'],
            'reputation': stats['reputation']
        } for ip, stats in sorted_ips]
    
    def _get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Retorna las alertas más recientes."""
        alerts = []
        for ip, stats in self.connections.items():
            if stats['alerts'] > 0:
                alerts.append({
                    'ip': ip,
                    'alerts': stats['alerts'],
                    'last_seen': stats['last_seen'].isoformat(),
                    'reputation': stats['reputation']
                })
        
        return sorted(alerts, 
                     key=lambda x: x['last_seen'],
                     reverse=True)[:limit]