try:
    import numpy as np
    import pandas as pd
except ImportError:
    print("Required dependencies not found. Please install required packages: pip install -r requirements.txt")
    raise

from typing import Tuple, List, Dict
from .utils import normalize_data, extract_features

class DataProcessor:
    def __init__(self, config: Dict):
        self.config = config
        self.feature_columns = [
            'packets_per_second',
            'bytes_per_second',
            'unique_ports',
            'connection_duration',
            'protocol_type',
            'tcp_flags',
            'packet_size_mean',
            'packet_size_std'
        ]

    def process_connection_data(self, connection_data: Dict) -> np.ndarray:
        """Procesa los datos de conexión para análisis de anomalías."""
        features = extract_features(connection_data)
        df = pd.DataFrame([features])
        
        # Normalizar datos
        normalized_data = normalize_data(df[self.feature_columns].values)
        return normalized_data

    def prepare_training_data(self, raw_data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepara datos para entrenamiento del modelo."""
        features_list = []
        for data in raw_data:
            features = extract_features(data)
            features_list.append(features)
        
        df = pd.DataFrame(features_list)
        X = normalize_data(df[self.feature_columns].values)
        
        # Para autoencoder, X_train = y_train
        return X, X

    def sequence_to_windows(self, data: np.ndarray, window_size: int) -> np.ndarray:
        """Convierte una secuencia en ventanas para LSTM."""
        windows = []
        for i in range(len(data) - window_size + 1):
            windows.append(data[i:i + window_size])
        return np.array(windows)