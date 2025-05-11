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
        # Load configurations
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        suricata_config_path = Path('config/suricata/suricata.yaml')
        with open(suricata_config_path, 'r') as f:
            self.suricata_config = yaml.safe_load(f)
        
        # Configure logging
        self.logger = logging.getLogger('ids_signatures.suricata_processor')
        
        # Initialize observer
        self.observer = Observer()
        
        # Internal state
        self.alerts: List[Dict] = []
        self.alert_counts: Dict[str, int] = {
            # Attack Categories
            'exploit_attempt': 0,
            'web_attack': 0,
            'malware_command_control': 0,
            'data_exfiltration': 0,
            'policy_violation': 0,
            'denial_of_service': 0,
            'reconnaissance': 0,
            'privilege_escalation': 0,
            
            # Specific Attack Types
            'sql_injection': 0,
            'xss': 0,
            'path_traversal': 0,
            'command_injection': 0,
            'file_inclusion': 0,
            'overflow_attempt': 0,
            
            # Malware Related
            'malware': 0,
            'ransomware': 0,
            'trojan': 0,
            'botnet': 0,
            'cryptominer': 0,
            
            # Protocol Anomalies
            'dns_anomaly': 0,
            'tls_anomaly': 0,
            'http_anomaly': 0,
            'smtp_anomaly': 0,
            
            # Access and Authentication
            'brute_force': 0,
            'default_login': 0,
            'unauthorized_access': 0,
            
            # Network Events
            'port_scan': 0,
            'network_scan': 0,
            'protocol_violation': 0,
            
            # Information Gathering
            'info_leak': 0,
            'suspicious_filename': 0,
            'suspicious_user_agent': 0
        }
        
        # Integration with anomaly analysis
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
        """Parsea un evento de alerta de Suricata siguiendo el formato EVE JSON."""
        try:
            alert = event.get('alert', {})
            flow = event.get('flow', {})
            http = event.get('http', {})
            tls = event.get('tls', {})
            
            parsed_alert = {
                'timestamp': event.get('timestamp', datetime.now().isoformat()),
                'event_type': 'alert',
                'type': self._classify_alert(alert),
                'alert': {
                    'signature_id': alert.get('signature_id', 0),
                    'signature': alert.get('signature', ''),
                    'category': alert.get('category', ''),
                    'severity': alert.get('severity', 0),
                    'rev': alert.get('rev', 0),
                    'gid': alert.get('gid', 1),
                    'action': alert.get('action', 'allowed'),
                    'classification': alert.get('classification', ''),
                },
                'source': {
                    'ip': event.get('src_ip', ''),
                    'port': event.get('src_port', ''),
                    'bytes': flow.get('bytes_toserver', 0),
                    'packets': flow.get('pkts_toserver', 0),
                },
                'destination': {
                    'ip': event.get('dest_ip', ''),
                    'port': event.get('dest_port', ''),
                    'bytes': flow.get('bytes_toclient', 0),
                    'packets': flow.get('pkts_toclient', 0),
                },
                'protocol': event.get('proto', ''),
                'app_proto': event.get('app_proto', ''),
                'flow_id': flow.get('flowid', ''),
                'community_id': event.get('community_id', ''),
                
                # HTTP specific fields if available
                'http': {
                    'hostname': http.get('hostname', ''),
                    'url': http.get('url', ''),
                    'http_method': http.get('http_method', ''),
                    'status': http.get('status', 0),
                    'user_agent': http.get('http_user_agent', '')
                } if http else None,
                
                # TLS specific fields if available
                'tls': {
                    'version': tls.get('version', ''),
                    'subject': tls.get('subject', ''),
                    'issuer': tls.get('issuer', ''),
                    'fingerprint': tls.get('fingerprint', ''),
                    'sni': tls.get('sni', '')
                } if tls else None,
                
                'raw': json.dumps(event)
            }
            
            # Remove None values
            return {k: v for k, v in parsed_alert.items() if v is not None}
            
        except Exception as e:
            self.logger.error(f"Error parseando alerta: {str(e)}")
            return None
    
    def _classify_alert(self, alert: Dict) -> str:
        """Enhanced alert classification based on category and signature."""
        category = alert.get('category', '').lower()
        signature = alert.get('signature', '').lower()
        class_type = alert.get('classification', '').lower()

        # Command and Control / Malware
        if 'command-and-control' in class_type or 'c2' in signature:
            return 'malware_command_control'
        elif 'malware' in category or 'trojan' in signature:
            return 'malware'
        elif 'ransomware' in signature:
            return 'ransomware'
        elif 'botcc' in signature or 'bot' in category:
            return 'botnet'
        elif 'coin' in signature or 'miner' in signature:
            return 'cryptominer'

        # Web Attacks
        elif 'sql' in signature and 'injection' in signature:
            return 'sql_injection'
        elif 'xss' in signature or 'cross-site' in signature:
            return 'xss'
        elif 'path' in signature and 'traversal' in signature:
            return 'path_traversal'
        elif 'command' in signature and 'injection' in signature:
            return 'command_injection'
        elif 'overflow' in signature or 'buffer' in signature:
            return 'overflow_attempt'
        elif 'include' in signature and ('local' in signature or 'remote' in signature):
            return 'file_inclusion'

        # Reconnaissance & Scanning
        elif 'scan' in category or 'scan' in signature:
            return 'port_scan'
        elif 'network-scan' in class_type:
            return 'network_scan'
        elif 'recon' in class_type:
            return 'reconnaissance'

        # Access & Authentication
        elif 'brute' in signature or 'bruteforce' in category:
            return 'brute_force'
        elif 'default-login' in class_type:
            return 'default_login'
        elif 'unauthorized' in signature:
            return 'unauthorized_access'

        # Protocol Anomalies
        elif 'dns' in category:
            return 'dns_anomaly'
        elif 'tls' in category:
            return 'tls_anomaly'
        elif 'http' in category:
            return 'http_anomaly'
        elif 'smtp' in category:
            return 'smtp_anomaly'

        # Policy & Information
        elif 'policy' in category:
            return 'policy_violation'
        elif 'info' in category and ('leak' in signature or 'disclosure' in signature):
            return 'info_leak'
        elif 'suspicious-filename' in class_type:
            return 'suspicious_filename'
        elif 'user-agent' in signature:
            return 'suspicious_user_agent'

        # Default for unclassified alerts
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
        """Envía la alerta al dashboard y a los clientes WebSocket conectados."""
        try:
            from modules.dashboard.app import socketio
            
            # Format alert for dashboard display
            dashboard_alert = {
                'timestamp': alert['timestamp'],
                'type': alert['type'],
                'severity': alert['alert']['severity'],
                'signature': alert['alert']['signature'],
                'source_ip': alert['source']['ip'],
                'dest_ip': alert['destination']['ip'],
                'protocol': alert['protocol'],
                'category': alert['alert']['category']
            }
            
            # Add HTTP details if available
            if alert.get('http'):
                dashboard_alert.update({
                    'url': alert['http']['url'],
                    'method': alert['http']['http_method'],
                    'user_agent': alert['http']['user_agent']
                })
            
            # Add TLS details if available
            if alert.get('tls'):
                dashboard_alert.update({
                    'tls_version': alert['tls']['version'],
                    'tls_sni': alert['tls']['sni']
                })
            
            # Emit to all connected clients
            socketio.emit('new_alert', dashboard_alert, namespace='/alerts')
            
            # Log the alert
            self.logger.info(f"Nueva alerta enviada al dashboard: {json.dumps(dashboard_alert)}")
            
        except Exception as e:
            self.logger.error(f"Error notificando al dashboard: {str(e)}")

    def get_alert_summary(self) -> Dict:
        """Genera un resumen de alertas para el dashboard."""
        try:
            # Calculate statistics
            total_alerts = len(self.alerts)
            alerts_by_severity = {
                'high': len([a for a in self.alerts if a['alert']['severity'] >= 3]),
                'medium': len([a for a in self.alerts if a['alert']['severity'] == 2]),
                'low': len([a for a in self.alerts if a['alert']['severity'] <= 1])
            }
            
            # Get top attackers and targets
            source_ips = {}
            target_ips = {}
            attack_types = {}
            
            for alert in self.alerts:
                src_ip = alert['source']['ip']
                dst_ip = alert['destination']['ip']
                attack = alert['type']
                
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
                target_ips[dst_ip] = target_ips.get(dst_ip, 0) + 1
                attack_types[attack] = attack_types.get(attack, 0) + 1
            
            # Sort and get top 10
            top_sources = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            top_targets = sorted(target_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:10]
            
            return {
                'total_alerts': total_alerts,
                'alerts_by_severity': alerts_by_severity,
                'top_sources': top_sources,
                'top_targets': top_targets,
                'top_attacks': top_attacks,
                'recent_alerts': [self._format_alert_for_display(a) for a in self.alerts[-10:]],
                'alert_counts': self.alert_counts
            }
            
        except Exception as e:
            self.logger.error(f"Error generando resumen de alertas: {str(e)}")
            return {}
            
    def _format_alert_for_display(self, alert: Dict) -> Dict:
        """Formatea una alerta para su visualización en el dashboard."""
        return {
            'timestamp': alert['timestamp'],
            'type': alert['type'],
            'severity': alert['alert']['severity'],
            'signature': alert['alert']['signature'],
            'source': f"{alert['source']['ip']}:{alert['source']['port']}",
            'destination': f"{alert['destination']['ip']}:{alert['destination']['port']}",
            'protocol': alert['protocol'],
            'category': alert['alert']['category']
        }
    
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

    def cleanup_old_alerts(self, max_age_days: int = 7):
        """Limpia alertas antiguas del sistema."""
        try:
            current_time = datetime.now()
            self.alerts = [
                alert for alert in self.alerts
                if (current_time - datetime.fromisoformat(alert['timestamp'])).days < max_age_days
            ]
            self.logger.info(f"Limpieza completada. {len(self.alerts)} alertas mantenidas.")
        except Exception as e:
            self.logger.error(f"Error durante la limpieza de alertas: {str(e)}")

    def handle_file_error(self, error_type: str, details: str):
        """Maneja errores relacionados con archivos."""
        try:
            self.logger.error(f"Error de archivo {error_type}: {details}")
            
            # Intentar recuperar el acceso al archivo
            if error_type == "permission":
                # Verificar permisos y notificar al administrador
                self.logger.critical("Error de permisos en archivo de alertas. Verificar permisos de suricata.")
            elif error_type == "not_found":
                # Intentar recrear el archivo o directorio
                self.logger.warning("Archivo de alertas no encontrado. Esperando a que Suricata lo cree.")
            elif error_type == "locked":
                # Esperar y reintentar
                time.sleep(1)
                self._process_new_alerts()
        except Exception as e:
            self.logger.error(f"Error manejando error de archivo: {str(e)}")

    def handle_network_error(self, error_type: str, details: str):
        """Maneja errores de red al notificar al dashboard."""
        try:
            self.logger.error(f"Error de red {error_type}: {details}")
            
            # Implementar reintento exponencial
            retry_count = 0
            max_retries = 3
            
            while retry_count < max_retries:
                try:
                    time.sleep(2 ** retry_count)
                    self._notify_dashboard({"error": "retry_connection"})
                    break
                except Exception:
                    retry_count += 1
                    
            if retry_count == max_retries:
                self.logger.critical("No se pudo reconectar con el dashboard")
        except Exception as e:
            self.logger.error(f"Error manejando error de red: {str(e)}")

    def export_alerts(self, format_type: str = 'json') -> str:
        """Exporta las alertas en varios formatos."""
        try:
            if format_type == 'json':
                return json.dumps(self.alerts, indent=2)
            elif format_type == 'csv':
                import csv
                import io
                output = io.StringIO()
                writer = csv.DictWriter(output, fieldnames=[
                    'timestamp', 'type', 'severity', 'signature',
                    'source_ip', 'source_port', 'dest_ip', 'dest_port',
                    'protocol', 'category'
                ])
                writer.writeheader()
                for alert in self.alerts:
                    writer.writerow({
                        'timestamp': alert['timestamp'],
                        'type': alert['type'],
                        'severity': alert['alert']['severity'],
                        'signature': alert['alert']['signature'],
                        'source_ip': alert['source']['ip'],
                        'source_port': alert['source']['port'],
                        'dest_ip': alert['destination']['ip'],
                        'dest_port': alert['destination']['port'],
                        'protocol': alert['protocol'],
                        'category': alert['alert']['category']
                    })
                return output.getvalue()
            else:
                raise ValueError(f"Formato no soportado: {format_type}")
        except Exception as e:
            self.logger.error(f"Error exportando alertas: {str(e)}")
            return ""

if __name__ == "__main__":
    processor = SuricataAlertProcessor()
    try:
        processor.start_monitoring()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        processor.stop_monitoring()