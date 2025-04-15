import logging
import yaml
from typing import Dict, Optional
from .evaluate import AnomalyEvaluator
from .model.train import ModelTrainer

class AlertAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger('anomaly_analysis.alert_analyzer')
        
        # Load configuration
        try:
            with open('config/global_config.yaml', 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            raise

        # Initialize evaluator and models
        self.evaluator = AnomalyEvaluator(self.config)
        self.model_trainer = ModelTrainer(self.config)
        
        # Load pre-trained models
        try:
            self.model_trainer.load_models('modules/anomaly_analysis/model/trained_models')
            self.evaluator.set_model(self.model_trainer.autoencoder)
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            raise
        
    def analyze(self, alert: Dict) -> Optional[Dict]:
        """Analyze an alert using ML models and return enriched data."""
        try:
            # Convert Suricata alert to connection data format
            connection_data = self._convert_alert_to_connection(alert)
            
            # Evaluate for anomalies
            is_anomaly, score, anomaly_alert = self.evaluator.evaluate_connection(connection_data)
            
            if (is_anomaly):
                # Enrich the original alert with anomaly information
                enriched_alert = alert.copy()
                enriched_alert.update({
                    'anomaly_detected': True,
                    'anomaly_score': score,
                    'anomaly_details': anomaly_alert['details'] if anomaly_alert else {}
                })
                return enriched_alert
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error analyzing alert: {str(e)}")
            return None
            
    def _convert_alert_to_connection(self, alert: Dict) -> Dict:
        """Convert a Suricata alert to the connection data format expected by the ML models."""
        return {
            'source_ip': alert['source']['ip'],
            'dest_ip': alert['destination']['ip'],
            'timestamp': alert['timestamp'],
            'protocol': alert['protocol'],
            'ports': {alert['source']['port'], alert['destination']['port']},
            # Extract more features from the raw alert if available
            'packets': alert.get('packets', 0),
            'bytes': alert.get('bytes', 0),
            'duration': 0,  # Will be calculated from packet timestamps if available
            'tcp_flags': alert.get('tcp_flags', 0)
        }

def get_analyzer(alert: Dict = None) -> AlertAnalyzer:
    """Factory function to get the appropriate analyzer."""
    return AlertAnalyzer()