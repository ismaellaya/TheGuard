try:
    import tensorflow as tf
    import numpy as np
except ImportError:
    print("Required dependencies not found. Please install required packages: pip install -r requirements.txt")
    raise

from typing import Dict, Tuple, List
from .autoencoder import create_autoencoder
from .lstm_model import create_lstm_autoencoder
from ..data_processing import DataProcessor

class ModelTrainer:
    def __init__(self, config: Dict):
        self.config = config
        self.data_processor = DataProcessor(config)
        self.autoencoder = None
        self.lstm_model = None
        
    def train_models(self, training_data: List[Dict]) -> Tuple[float, float]:
        """Entrena ambos modelos con los datos proporcionados."""
        # Preparar datos
        X, y = self.data_processor.prepare_training_data(training_data)
        
        # Entrenar autoencoder
        self.autoencoder = create_autoencoder(self.config)
        ae_history = self.autoencoder.fit(
            X, y,
            epochs=self.config['ml_config']['epochs'],
            batch_size=self.config['ml_config']['batch_size'],
            validation_split=self.config['ml_config']['validation_split']
        )
        
        # Preparar datos para LSTM
        window_size = self.config.get('timesteps', 10)
        X_sequences = self.data_processor.sequence_to_windows(X, window_size)
        
        # Entrenar LSTM
        self.lstm_model = create_lstm_autoencoder(self.config)
        lstm_history = self.lstm_model.fit(
            X_sequences, X_sequences,
            epochs=self.config['ml_config']['epochs'],
            batch_size=self.config['ml_config']['batch_size'],
            validation_split=self.config['ml_config']['validation_split']
        )
        
        return (
            np.min(ae_history.history['val_loss']),
            np.min(lstm_history.history['val_loss'])
        )
    
    def save_models(self, base_path: str):
        """Guarda los modelos entrenados."""
        if self.autoencoder:
            self.autoencoder.save(f"{base_path}/autoencoder")
        if self.lstm_model:
            self.lstm_model.save(f"{base_path}/lstm")
    
    def load_models(self, base_path: str):
        """Carga modelos previamente entrenados."""
        try:
            self.autoencoder = tf.keras.models.load_model(f"{base_path}/autoencoder")
            self.lstm_model = tf.keras.models.load_model(f"{base_path}/lstm")
        except Exception as e:
            print(f"Error loading models: {str(e)}")
            return False
        return True