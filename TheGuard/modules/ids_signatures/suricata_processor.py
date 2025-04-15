import os
import yaml
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from modules.anomaly_analysis.alert_analyzer import get_analyzer

class SuricataAlertProcessor(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        # Cargar configuración global
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Cargar configuración específica de Suricata
        suricata_config_path = Path('config/suricata/suricata.yaml')
        with open(suricata_config_path, 'r') as f:
            self.suricata_config = yaml.safe_load(f)
        
        # Configurar logging
        self.logger = logging.getLogger('ids_signatures.suricata_processor')
        
        # Inicializar observer para monitoreo de archivos
        self.observer = Observer()
        
        # Estado interno
        self.alerts: List[Dict] = []
        self.alert_counts: Dict[str, int] = {
            'sql_injection': 0,
            'xss': 0,
            'path_traversal': 0,
            'command_injection': 0,
            'port_scan': 0,
            'brute_force': 0,
            'malware': 0,
            'dns_anomaly': 0,
            'ddos': 0,
            'tls_anomaly': 0,
            'http_anomaly': 0,
            'botnet': 0,
            'exploit': 0,
            'phishing': 0,
            'policy': 0,
            'web_attack': 0,
            'coin_miner': 0,
            'info_leak': 0,
            'mobile_malware': 0
        }
        
        # Integración con análisis de anomalías
        self.alert_analyzer = get_analyzer()
    
    def start_monitoring(self):
        """Inicia el monitoreo del archivo de alertas de Suricata."""
        try:
            # Obtener la ruta del archivo eve.json de la configuración de Suricata
            eve_log_config = next(
                (item for item in self.suricata_config.get('outputs', [])
                 if item.get('eve-log', {}).get('enabled')),
                None
            )
            
            if not eve_log_config:
                raise ValueError("No se encontró configuración de eve-log en suricata.yaml")
                
            eve_json_path = Path(eve_log_config['eve-log']['filename'])
            if not eve_json_path.is_absolute():
                eve_json_path = Path('/var/log/suricata') / eve_json_path
            
            self.observer.schedule(self, str(eve_json_path.parent), recursive=False)
            self.observer.start()
            self.logger.info(f"Iniciado monitoreo de alertas en {eve_json_path}")
            
            # Procesar alertas existentes al inicio
            self._process_new_alerts()
        except Exception as e:
            self.logger.error(f"Error al iniciar monitoreo: {str(e)}")
            raise

    def on_modified(self, event):
        """Maneja las modificaciones en el archivo eve.json."""
        if event.src_path.endswith(self.config['suricata']['eve_json_path']):
            self._process_new_alerts()
    
    def _process_new_alerts(self):
        """Procesa las nuevas alertas del archivo eve.json."""
        try:
            with open(self.config['suricata']['eve_json_path'], 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            alert = self._parse_alert(event)
                            if alert:
                                # Actualizar estadísticas
                                self._update_statistics(alert)
                                
                                # Analizar anomalías
                                anomaly_alert = self.alert_analyzer.analyze(alert)
                                if anomaly_alert:
                                    self._update_statistics(anomaly_alert)
                                
                                # Notificar al dashboard
                                self._notify_dashboard(alert)
                                if anomaly_alert:
                                    self._notify_dashboard(anomaly_alert)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.logger.error(f"Error procesando alertas: {str(e)}")
    
    def _parse_alert(self, event: Dict) -> Optional[Dict]:
        """Parsea un evento de alerta de Suricata."""
        try:
            alert = event.get('alert', {})
            return {
                'timestamp': event.get('timestamp', datetime.now().isoformat()),
                'type': self._classify_alert(alert),
                'message': alert.get('signature', ''),
                'category': alert.get('category', ''),
                'severity': alert.get('severity', 0),
                'source': {
                    'ip': event.get('src_ip', ''),
                    'port': event.get('src_port', '')
                },
                'destination': {
                    'ip': event.get('dest_ip', ''),
                    'port': event.get('dest_port', '')
                },
                'protocol': event.get('proto', ''),
                'raw': json.dumps(event)
            }
        except Exception as e:
            self.logger.error(f"Error parseando alerta: {str(e)}")
        return None
    
    def _classify_alert(self, alert: Dict) -> str:
        """Clasifica el tipo de alerta basado en su categoría y firma."""
        category = alert.get('category', '').lower()
        signature = alert.get('signature', '').lower()
        
        # Clasificación específica de Emerging Threats
        if 'botcc' in signature or 'bot' in category:
            return 'botnet'
        elif 'exploit' in category or 'exploit' in signature:
            return 'exploit'
        elif 'phishing' in signature:
            return 'phishing'
        elif 'policy' in category:
            return 'policy'
        elif 'web' in category and 'attack' in signature:
            return 'web_attack'
        elif 'coin' in signature or 'miner' in signature:
            return 'coin_miner'
        elif 'info' in category and ('leak' in signature or 'disclosure' in signature):
            return 'info_leak'
        elif 'mobile' in category or 'mobile_malware' in signature:
            return 'mobile_malware'
        
        # Clasificaciones estándar
        elif 'sql' in signature:
            return 'sql_injection'
        elif 'xss' in signature or 'cross-site' in signature:
            return 'xss'
        elif 'traversal' in signature:
            return 'path_traversal'
        elif 'command' in signature and 'injection' in signature:
            return 'command_injection'
        elif 'scan' in category or 'scan' in signature:
            return 'port_scan'
        elif 'brute' in signature or 'bruteforce' in category:
            return 'brute_force'
        elif 'malware' in category or 'trojan' in signature:
            return 'malware'
        elif 'dns' in category:
            return 'dns_anomaly'
        elif 'ddos' in category or 'flood' in signature:
            return 'ddos'
        elif 'tls' in category:
            return 'tls_anomaly'
        elif 'http' in category:
            return 'http_anomaly'
        return 'other'
    
    def _update_statistics(self, alert: Dict):
        """Actualiza las estadísticas internas de alertas."""
        self.alerts.append(alert)
        if len(self.alerts) > 1000:  # Mantener solo las últimas 1000 alertas
            self.alerts = self.alerts[-1000:]
        
        alert_type = alert['type']
        if alert_type in self.alert_counts:
            self.alert_counts[alert_type] += 1
    
    def _notify_dashboard(self, alert: Dict):
        """Envía la alerta al dashboard para su visualización."""
        self.logger.info(f"Nueva alerta: {json.dumps(alert)}")
    
    def get_statistics(self) -> Dict:
        """Retorna estadísticas actuales de alertas."""
        return {
            'total_alerts': len(self.alerts),
            'alert_counts': self.alert_counts,
            'recent_alerts': self.alerts[-10:],  # Últimas 10 alertas
            'alert_types': list(set(alert['type'] for alert in self.alerts))
        }
    
    def stop_monitoring(self):
        """Detiene el monitoreo de alertas."""
        self.observer.stop()
        self.observer.join()
        self.logger.info("Monitoreo de alertas detenido")

if __name__ == "__main__":
    processor = SuricataAlertProcessor()
    try:
        processor.start_monitoring()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        processor.stop_monitoring()