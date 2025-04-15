import numpy as np
from typing import Dict, Tuple, Optional
from .utils import calculate_anomaly_score
from .data_processing import DataProcessor

class AnomalyEvaluator:
    def __init__(self, config: Dict):
        self.config = config
        self.threshold = config['ml_config']['threshold']
        self.data_processor = DataProcessor(config)
    
    def evaluate_connection(self, connection_data: Dict) -> Tuple[bool, float, Optional[Dict]]:
        """Evalúa si una conexión es anómala."""
        try:
            # Procesar datos
            processed_data = self.data_processor.process_connection_data(connection_data)
            
            # Obtener predicción del modelo
            reconstruction = self.model.predict(processed_data)
            
            # Calcular error de reconstrucción
            reconstruction_error = np.mean(np.square(processed_data - reconstruction))
            
            # Calcular score de anomalía
            anomaly_score = calculate_anomaly_score(reconstruction_error, self.threshold)
            
            # Determinar si es anomalía
            is_anomaly = anomaly_score > 1.0
            
            if is_anomaly:
                alert = self._generate_alert(connection_data, anomaly_score)
                return True, anomaly_score, alert
                
            return False, anomaly_score, None
            
        except Exception as e:
            print(f"Error evaluating connection: {str(e)}")
            return False, 0.0, None
    
    def _generate_alert(self, connection_data: Dict, anomaly_score: float) -> Dict:
        """Genera una alerta para una anomalía detectada."""
        return {
            'type': 'anomaly',
            'source_ip': connection_data.get('source_ip'),
            'dest_ip': connection_data.get('dest_ip'),
            'score': anomaly_score,
            'timestamp': connection_data.get('timestamp'),
            'details': {
                'packets': connection_data.get('packets'),
                'bytes': connection_data.get('bytes'),
                'duration': connection_data.get('duration'),
                'ports': list(connection_data.get('ports', set()))
            }
        }
    
    def set_model(self, model):
        """Establece el modelo a usar para evaluación."""
        self.model = model