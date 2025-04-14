from typing import Generator, Optional, Dict
import os
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from .snort_processor import SnortAlertProcessor

class SnortAlertIntegration:
    def __init__(self):
        self.alert_processor = SnortAlertProcessor()
        self.logger = logging.getLogger('ids_firmas.integration')
        
    def follow(self, log_file) -> Generator[str, None, None]:
        """Emula 'tail -f' para leer nuevas líneas del archivo de log en tiempo real."""
        log_file.seek(0, os.SEEK_END)
        
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line
    
    def start_monitoring(self, log_file_path: str = "/var/log/snort/alert"):
        """Inicia el monitoreo del archivo de log de Snort."""
        self.logger.info(f"Iniciando monitoreo del archivo: {log_file_path}")
        
        try:
            # Asegurar que el directorio de logs existe
            log_dir = os.path.dirname(log_file_path)
            os.makedirs(log_dir, exist_ok=True)
            
            # Crear el archivo si no existe
            if not os.path.exists(log_file_path):
                Path(log_file_path).touch()
            
            # Iniciar el procesador de alertas
            self.alert_processor.start_monitoring()
            
            with open(log_file_path, "r") as log_file:
                log_lines = self.follow(log_file)
                for line in log_lines:
                    self._process_alert(line)
                    
        except KeyboardInterrupt:
            self.logger.info("Monitoreo detenido por el usuario")
        except Exception as e:
            self.logger.error(f"Error durante el monitoreo: {str(e)}")
            raise
        finally:
            self.alert_processor.stop_monitoring()
    
    def _process_alert(self, alert_line: str):
        """Procesa una línea de alerta de Snort."""
        try:
            alert_line = alert_line.strip()
            if not alert_line:
                return
            
            # El procesamiento real se hace en el SnortAlertProcessor
            self.alert_processor._process_new_alerts()
            
        except Exception as e:
            self.logger.error(f"Error procesando alerta: {str(e)}")
    
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas actuales de alertas."""
        return self.alert_processor.get_statistics()
    
    def stop_monitoring(self):
        """Detiene el monitoreo de alertas."""
        self.alert_processor.stop_monitoring()

# Instancia global para usar en toda la aplicación
_integration = None

def get_integration() -> SnortAlertIntegration:
    """Retorna una instancia única de la integración de alertas."""
    global _integration
    if _integration is None:
        _integration = SnortAlertIntegration()
    return _integration