import requests
import logging
from typing import Dict, Optional
import yaml

class AbuseIPDBClient:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        self.api_key = config['apis']['abuseipdb']['api_key']
        self.base_url = config['apis']['abuseipdb']['base_url']
        self.logger = logging.getLogger('ip_monitoring.abuse_ipdb')
    
    def check_ip(self, ip: str) -> Optional[Dict]:
        """Consulta la reputación de una IP en AbuseIPDB."""
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params=params
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'abuse_confidence_score': data['data']['abuseConfidenceScore'],
                    'total_reports': data['data'].get('totalReports', 0),
                    'last_reported_at': data['data'].get('lastReportedAt'),
                    'is_public': data['data'].get('isPublic', True),
                    'usage_type': data['data'].get('usageType', 'unknown'),
                    'country_code': data['data'].get('countryCode', 'unknown')
                }
            
            self.logger.error(f"Error checking IP {ip}: {response.status_code}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking IP {ip}: {str(e)}")
            return None
    
    def report_ip(self, ip: str, categories: list, comment: str) -> bool:
        """Reporta una IP maliciosa a AbuseIPDB."""
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
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
                self.logger.info(f"Successfully reported IP {ip}")
                return True
            
            self.logger.error(f"Error reporting IP {ip}: {response.status_code}")
            return False
            
        except Exception as e:
            self.logger.error(f"Error reporting IP {ip}: {str(e)}")
            return False