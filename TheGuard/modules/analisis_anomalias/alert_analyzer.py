import numpy as np
import logging
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from .model.autoencoder import TrafficAutoencoder
from .model.lstm_model import TrafficLSTM

class AlertAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger('analisis_anomalias.alert_analyzer')
        
        # Ventana de tiempo para análisis (15 minutos)
        self.window_size = timedelta(minutes=15)
        
        # Características a analizar
        self.feature_names = [
            'sql_injection', 'xss', 'command_injection',
            'port_scan', 'brute_force', 'malware',
            'dns_anomaly', 'ddos'
        ]
        
        # Inicializar modelos
        self.autoencoder = TrafficAutoencoder(input_dim=len(self.feature_names))
        self.lstm = TrafficLSTM(
            sequence_length=10,
            n_features=len(self.feature_names)
        )
        
        # Buffer para almacenar alertas recientes
        self.alert_buffer: List[Dict] = []
        
        try:
            # Cargar modelos pre-entrenados si existen
            self.autoencoder.load_model('modules/analisis_anomalias/model/autoencoder_model')
            self.lstm.load_model('modules/analisis_anomalias/model/lstm_model')
            self.logger.info("Modelos cargados exitosamente")
        except Exception as e:
            self.logger.warning(f"No se pudieron cargar los modelos pre-entrenados: {e}")
            self.logger.info("Los modelos necesitarán ser entrenados con nuevos datos")
    
    def process_alert(self, alert: Dict) -> Optional[Dict]:
        """
        Procesa una nueva alerta y detecta patrones anómalos.
        Retorna una alerta de anomalía si se detecta un patrón sospechoso.
        """
        try:
            # Añadir alerta al buffer y limpiar alertas antiguas
            self._update_alert_buffer(alert)
            
            # Extraer características del buffer actual
            features = self._extract_features()
            
            # Si no hay suficientes datos, retornar None
            if features is None:
                return None
            
            # Detectar anomalías usando ambos modelos
            autoencoder_anomaly = self._check_autoencoder_anomaly(features)
            lstm_anomaly = self._check_lstm_anomaly(features)
            
            # Si alguno de los modelos detecta una anomalía
            if autoencoder_anomaly or lstm_anomaly:
                return self._create_anomaly_alert(
                    alert,
                    autoencoder_score=autoencoder_anomaly,
                    lstm_score=lstm_anomaly
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error procesando alerta para análisis: {str(e)}")
            return None
    
    def _update_alert_buffer(self, alert: Dict):
        """Actualiza el buffer de alertas, manteniendo solo las más recientes."""
        now = datetime.now()
        cutoff = now - self.window_size
        
        # Añadir nueva alerta
        self.alert_buffer.append(alert)
        
        # Eliminar alertas antiguas
        self.alert_buffer = [
            a for a in self.alert_buffer
            if datetime.fromisoformat(a['timestamp']) > cutoff
        ]
    
    def _extract_features(self) -> Optional[np.ndarray]:
        """Extrae características del buffer de alertas actual."""
        if not self.alert_buffer:
            return None
        
        # Contar ocurrencias de cada tipo de alerta
        feature_counts = {name: 0 for name in self.feature_names}
        
        for alert in self.alert_buffer:
            alert_type = alert.get('type')
            if alert_type in feature_counts:
                feature_counts[alert_type] += 1
        
        # Convertir a array numpy
        features = np.array([feature_counts[name] for name in self.feature_names])
        
        # Normalizar características
        features = features / (np.max(features) if np.max(features) > 0 else 1)
        
        return features.reshape(1, -1)
    
    def _check_autoencoder_anomaly(self, features: np.ndarray) -> float:
        """Detecta anomalías usando el autoencoder."""
        try:
            is_anomaly, score = self.autoencoder.detect_anomalies(features)
            return float(score[0]) if is_anomaly[0] else 0.0
        except Exception as e:
            self.logger.error(f"Error en detección con autoencoder: {str(e)}")
            return 0.0
    
    def _check_lstm_anomaly(self, features: np.ndarray) -> float:
        """Detecta anomalías usando el modelo LSTM."""
        try:
            # Preparar secuencia para LSTM
            sequence = np.repeat(features, 10, axis=0)
            is_anomaly, score = self.lstm.detect_anomalies(sequence)
            return float(score[0]) if is_anomaly[0] else 0.0
        except Exception as e:
            self.logger.error(f"Error en detección con LSTM: {str(e)}")
            return 0.0
    
    def _create_anomaly_alert(self, 
                            original_alert: Dict,
                            autoencoder_score: float,
                            lstm_score: float) -> Dict:
        """Crea una alerta de anomalía basada en los resultados del análisis."""
        return {
            'timestamp': datetime.now().isoformat(),
            'type': 'anomaly',
            'message': 'Patrón anómalo detectado en secuencia de alertas',
            'severity': 'danger',
            'source_alert': original_alert,
            'details': {
                'autoencoder_score': autoencoder_score,
                'lstm_score': lstm_score,
                'alerts_in_window': len(self.alert_buffer),
                'alert_types': list(set(a['type'] for a in self.alert_buffer))
            }
        }

# Instancia global para usar en toda la aplicación
_analyzer = None

def get_analyzer() -> AlertAnalyzer:
    """Retorna una instancia única del analizador de alertas."""
    global _analyzer
    if _analyzer is None:
        _analyzer = AlertAnalyzer()
    return _analyzer