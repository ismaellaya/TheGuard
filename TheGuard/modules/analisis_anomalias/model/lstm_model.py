import tensorflow as tf
import numpy as np
from typing import Tuple, List, Optional
import logging
from datetime import datetime

class TrafficLSTM:
    def __init__(self, sequence_length: int, n_features: int, hidden_units: int = 64):
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.hidden_units = hidden_units
        self.logger = logging.getLogger('analisis_anomalias.lstm')
        
        # Crear modelo
        self.model = self._build_model()
        self.history = None
        self.threshold = None
    
    def _build_model(self) -> tf.keras.Model:
        """Construye el modelo LSTM para análisis de secuencias temporales."""
        model = tf.keras.Sequential([
            # Capa LSTM bidireccional para capturar patrones en ambas direcciones
            tf.keras.layers.Bidirectional(
                tf.keras.layers.LSTM(
                    self.hidden_units,
                    return_sequences=True,
                    activation='tanh'
                ),
                input_shape=(self.sequence_length, self.n_features)
            ),
            
            # Dropout para regularización
            tf.keras.layers.Dropout(0.2),
            
            # Segunda capa LSTM
            tf.keras.layers.Bidirectional(
                tf.keras.layers.LSTM(
                    self.hidden_units // 2,
                    return_sequences=True
                )
            ),
            
            # Dropout
            tf.keras.layers.Dropout(0.2),
            
            # Capa densa con activación suave
            tf.keras.layers.Dense(
                self.hidden_units // 2,
                activation='relu'
            ),
            
            # Capa de salida para predicción de la siguiente secuencia
            tf.keras.layers.Dense(self.n_features)
        ])
        
        # Compilar modelo
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return model
    
    def prepare_sequences(self, data: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Prepara secuencias temporales para entrenamiento."""
        X, y = [], []
        
        for i in range(len(data) - self.sequence_length):
            X.append(data[i:i + self.sequence_length])
            y.append(data[i + self.sequence_length])
        
        return np.array(X), np.array(y)
    
    def train(self, X_train: np.ndarray, X_val: np.ndarray, 
             batch_size: int = 32, epochs: int = 100) -> tf.keras.callbacks.History:
        """Entrena el modelo LSTM."""
        try:
            # Preparar secuencias
            X_train_seq, y_train_seq = self.prepare_sequences(X_train)
            X_val_seq, y_val_seq = self.prepare_sequences(X_val)
            
            # Callbacks
            early_stopping = tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
            
            reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.2,
                patience=5,
                min_lr=1e-6
            )
            
            # Entrenar modelo
            self.history = self.model.fit(
                X_train_seq, y_train_seq,
                validation_data=(X_val_seq, y_val_seq),
                epochs=epochs,
                batch_size=batch_size,
                callbacks=[early_stopping, reduce_lr],
                verbose=1
            )
            
            # Calcular umbral de anomalía
            self._calculate_threshold(X_val_seq, y_val_seq)
            
            return self.history
            
        except Exception as e:
            self.logger.error(f"Error durante el entrenamiento: {str(e)}")
            raise
    
    def _calculate_threshold(self, X_val: np.ndarray, y_val: np.ndarray, 
                          percentile: float = 95):
        """Calcula el umbral para detección de anomalías."""
        try:
            # Obtener predicciones
            predictions = self.model.predict(X_val)
            
            # Calcular errores de predicción
            errors = np.mean(np.square(predictions - y_val), axis=1)
            
            # Establecer umbral
            self.threshold = np.percentile(errors, percentile)
            
            self.logger.info(f"Umbral de anomalía calculado: {self.threshold}")
            
        except Exception as e:
            self.logger.error(f"Error calculando umbral: {str(e)}")
            raise
    
    def detect_anomalies(self, sequences: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detecta anomalías en secuencias temporales.
        Retorna (is_anomaly, anomaly_scores).
        """
        if self.threshold is None:
            raise ValueError("El modelo debe ser entrenado antes de detectar anomalías")
        
        try:
            # Obtener predicciones
            predictions = self.model.predict(sequences)
            
            # Calcular errores de predicción
            errors = np.mean(np.square(predictions - sequences[:, -1, :]), axis=1)
            
            # Determinar anomalías
            is_anomaly = errors > self.threshold
            
            # Normalizar scores
            anomaly_scores = errors / self.threshold
            
            return is_anomaly, anomaly_scores
            
        except Exception as e:
            self.logger.error(f"Error detectando anomalías: {str(e)}")
            raise
    
    def save_model(self, path: str):
        """Guarda el modelo entrenado."""
        try:
            self.model.save(path)
            # Guardar también el umbral y parámetros
            params = {
                'threshold': self.threshold,
                'sequence_length': self.sequence_length,
                'n_features': self.n_features,
                'hidden_units': self.hidden_units
            }
            np.save(f"{path}_params.npy", params)
            self.logger.info(f"Modelo guardado en {path}")
        except Exception as e:
            self.logger.error(f"Error guardando modelo: {str(e)}")
            raise
    
    def load_model(self, path: str):
        """Carga un modelo previamente guardado."""
        try:
            self.model = tf.keras.models.load_model(path)
            # Cargar parámetros
            params = np.load(f"{path}_params.npy", allow_pickle=True).item()
            self.threshold = params['threshold']
            self.sequence_length = params['sequence_length']
            self.n_features = params['n_features']
            self.hidden_units = params['hidden_units']
            self.logger.info(f"Modelo cargado desde {path}")
        except Exception as e:
            self.logger.error(f"Error cargando modelo: {str(e)}")
            raise
    
    def predict_next_sequence(self, sequence: np.ndarray) -> np.ndarray:
        """Predice la siguiente secuencia de valores."""
        if sequence.shape != (1, self.sequence_length, self.n_features):
            sequence = sequence.reshape(1, self.sequence_length, self.n_features)
        
        try:
            return self.model.predict(sequence)[0]
        except Exception as e:
            self.logger.error(f"Error prediciendo secuencia: {str(e)}")
            raise
    
    def get_sequence_importance(self, sequence: np.ndarray) -> np.ndarray:
        """
        Calcula la importancia de cada punto en la secuencia usando
        la magnitud del error de predicción.
        """
        try:
            # Asegurar forma correcta
            if sequence.shape != (1, self.sequence_length, self.n_features):
                sequence = sequence.reshape(1, self.sequence_length, self.n_features)
            
            # Predecir
            prediction = self.model.predict(sequence)
            
            # Calcular error por característica
            errors = np.abs(prediction - sequence[:, -1, :])
            
            # Normalizar importancias
            importance = errors / np.sum(errors)
            
            return importance[0]
            
        except Exception as e:
            self.logger.error(f"Error calculando importancia: {str(e)}")
            raise