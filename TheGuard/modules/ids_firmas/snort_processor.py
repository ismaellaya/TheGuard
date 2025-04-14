import os
import yaml
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from modules.analisis_anomalias.alert_analyzer import get_analyzer

class SnortAlertProcessor(FileSystemEventHandler):
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
        self.logger = logging.getLogger('ids_firmas.snort_processor')
        
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
            'ddos': 0
        }
        
        # Inicializar el observador de archivos
        self.observer = Observer()
        
        # Inicializar analizador de anomalías
        self.alert_analyzer = get_analyzer()
    
    def start_monitoring(self):
        """Inicia el monitoreo del archivo de alertas de Snort."""
        try:
            alert_path = self.config['snort']['alert_file']
            self.observer.schedule(self, os.path.dirname(alert_path), recursive=False)
            self.observer.start()
            self.logger.info(f"Iniciado monitoreo de alertas en {alert_path}")
        except Exception as e:
            self.logger.error(f"Error al iniciar monitoreo: {str(e)}")
            raise
    
    def on_modified(self, event):
        """Maneja las modificaciones en el archivo de alertas."""
        if event.src_path.endswith(self.config['snort']['alert_file']):
            self._process_new_alerts()
    
    def _process_new_alerts(self):
        """Procesa las nuevas alertas del archivo de Snort."""
        try:
            with open(self.config['snort']['alert_file'], 'r') as f:
                for line in f:
                    if '[**]' in line:  # Formato típico de alerta Snort
                        alert = self._parse_alert(line)
                        if alert:
                            # Actualizar estadísticas
                            self._update_statistics(alert)
                            
                            # Analizar anomalías
                            anomaly_alert = self.alert_analyzer.process_alert(alert)
                            if anomaly_alert:
                                self._update_statistics(anomaly_alert)
                            
                            # Notificar al dashboard
                            self._notify_dashboard(alert)
                            if anomaly_alert:
                                self._notify_dashboard(anomaly_alert)
                                
        except Exception as e:
            self.logger.error(f"Error procesando alertas: {str(e)}")
    
    def _parse_alert(self, alert_line: str) -> Optional[Dict]:
        """Parsea una línea de alerta de Snort."""
        try:
            # Formato típico: [**] [1:1000001:1] SQL Injection - SELECT detectado [**]
            parts = alert_line.split('[**]')
            if len(parts) >= 2:
                alert_info = parts[1].strip()
                classification = self._classify_alert(alert_info)
                
                return {
                    'timestamp': datetime.now().isoformat(),
                    'type': classification,
                    'message': alert_info,
                    'raw': alert_line.strip(),
                    'severity': self._get_severity(classification)
                }
        except Exception as e:
            self.logger.error(f"Error parseando alerta: {str(e)}")
        return None
    
    def _classify_alert(self, alert_info: str) -> str:
        """Clasifica el tipo de alerta basado en su contenido."""
        alert_info = alert_info.lower()
        if 'sql' in alert_info:
            return 'sql_injection'
        elif 'xss' in alert_info or 'script' in alert_info:
            return 'xss'
        elif 'path traversal' in alert_info:
            return 'path_traversal'
        elif 'command injection' in alert_info:
            return 'command_injection'
        elif 'scan' in alert_info:
            return 'port_scan'
        elif 'brute force' in alert_info:
            return 'brute_force'
        elif 'malware' in alert_info or 'trojan' in alert_info:
            return 'malware'
        elif 'dns' in alert_info:
            return 'dns_anomaly'
        elif 'flood' in alert_info or 'dos' in alert_info:
            return 'ddos'
        return 'other'
    
    def _get_severity(self, alert_type: str) -> str:
        """Determina la severidad de la alerta según su tipo."""
        high_severity = {'sql_injection', 'command_injection', 'malware'}
        medium_severity = {'xss', 'path_traversal', 'brute_force'}
        
        if alert_type in high_severity:
            return 'danger'
        elif alert_type in medium_severity:
            return 'warning'
        return 'info'
    
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
        # TODO: Implementar integración con el dashboard
        # Por ahora solo registramos la alerta
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