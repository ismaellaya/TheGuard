from typing import Generator, Optional, Dict
import os
import time
import json
import logging
import yaml
from pathlib import Path
from datetime import datetime
from .suricata_processor import SuricataAlertProcessor, get_integration

class IDSIntegration:
    def __init__(self):
        self.logger = logging.getLogger('ids_signatures.integration')
        self._load_configuration()
        self.alert_processor = SuricataAlertProcessor()

    def _load_configuration(self):
        """Carga la configuración del IDS desde el archivo global."""
        try:
            config_path = Path('config/global_config.yaml')
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
                
            # Verificar que Suricata está instalado y configurado
            if not Path('/etc/suricata').exists():
                self.logger.warning("Suricata no está instalado. Ejecute scripts/setup.sh primero.")
        except Exception as e:
            self.logger.error(f"Error al cargar configuración: {str(e)}")
            raise
        
    def start_monitoring(self):
        """Inicia el monitoreo de alertas IDS."""
        try:
            self._verify_suricata_status()
            self.alert_processor.start_monitoring()
        except Exception as e:
            self.logger.error(f"Error al iniciar monitoreo: {str(e)}")
            raise
    
    def _verify_suricata_status(self):
        """Verifica el estado de Suricata antes de iniciar el monitoreo."""
        try:
            import subprocess
            result = subprocess.run(['systemctl', 'is-active', 'suricata'], 
                                 capture_output=True, text=True)
            if result.stdout.strip() != 'active':
                raise RuntimeError("Suricata no está activo")
        except Exception as e:
            self.logger.error(f"Error al verificar estado de Suricata: {str(e)}")
            raise
    
    def stop_monitoring(self):
        """Detiene el monitoreo de alertas."""
        self.alert_processor.stop_monitoring()
    
    def get_statistics(self) -> Dict:
        """Retorna estadísticas actuales de alertas."""
        return self.alert_processor.get_statistics()
    
    def update_rules(self):
        """Actualiza las reglas de Suricata."""
        try:
            import subprocess
            self.logger.info("Actualizando reglas de Suricata...")
            result = subprocess.run(['suricata-update'], 
                                 capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Error al actualizar reglas: {result.stderr}")
            self.logger.info("Reglas actualizadas correctamente")
            
            # Reiniciar Suricata para aplicar las nuevas reglas
            subprocess.run(['systemctl', 'restart', 'suricata'])
        except Exception as e:
            self.logger.error(f"Error en actualización de reglas: {str(e)}")
            raise

# Instancia global para usar en toda la aplicación
_integration = None

def get_integration() -> IDSIntegration:
    """Retorna una instancia única de la integración de alertas."""
    global _integration
    if _integration is None:
        _integration = IDSIntegration()
    return _integration
