import requests
import yaml
import logging
from typing import Optional
from datetime import datetime, timedelta

class AbuseIPDBClient:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.api_key = self.config['apis']['abuseipdb']['api_key']
        self.base_url = self.config['apis']['abuseipdb']['base_url']
        
        # Configurar logging
        self.logger = logging.getLogger('monitorizacion_ip.abuseipdb')
        
        # Cache local para evitar consultas repetidas
        self._cache = {}
        self._cache_duration = timedelta(hours=1)
    
    def check_ip(self, ip: str) -> Optional[int]:
        """
        Verifica la reputación de una IP usando AbuseIPDB.
        Retorna una puntuación de confianza (0-100) o None si hay error.
        """
        # Verificar cache primero
        if ip in self._cache:
            cache_entry = self._cache[ip]
            if datetime.now() - cache_entry['timestamp'] < self._cache_duration:
                return cache_entry['score']
        
        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 30,
                'verbose': True
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                score = data['data'].get('abuseConfidenceScore', 0)
                
                # Actualizar cache
                self._cache[ip] = {
                    'score': score,
                    'timestamp': datetime.now()
                }
                
                return score
            else:
                self.logger.error(
                    f"Error consultando AbuseIPDB: {response.status_code} - {response.text}"
                )
                return None
                
        except Exception as e:
            self.logger.error(f"Error al verificar IP {ip}: {str(e)}")
            return None
    
    def report_ip(self, ip: str, categories: list, comment: str) -> bool:
        """
        Reporta una IP maliciosa a AbuseIPDB.
        Categorías según: https://www.abuseipdb.com/categories
        """
        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }
            
            data = {
                'ip': ip,
                'categories': ','.join(map(str, categories)),
                'comment': comment
            }
            
            response = requests.post(
                f"{self.base_url}/report",
                headers=headers,
                data=data
            )
            
            if response.status_code == 200:
                self.logger.info(f"IP {ip} reportada exitosamente a AbuseIPDB")
                return True
            else:
                self.logger.error(
                    f"Error reportando IP: {response.status_code} - {response.text}"
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error al reportar IP {ip}: {str(e)}")
            return False

# Cliente global para usar en toda la aplicación
_client = None

def get_client() -> AbuseIPDBClient:
    """Retorna una instancia única del cliente de AbuseIPDB."""
    global _client
    if _client is None:
        _client = AbuseIPDBClient()
    return _client

def check_ip_reputation(ip: str) -> Optional[int]:
    """
    Función auxiliar para verificar la reputación de una IP.
    Retorna una puntuación de 0 a 100, donde 100 es la peor reputación.
    """
    client = get_client()
    return client.check_ip(ip)

def report_malicious_ip(ip: str, reason: str, categories: list) -> bool:
    """
    Función auxiliar para reportar una IP maliciosa.
    """
    client = get_client()
    return client.report_ip(ip, categories, reason)