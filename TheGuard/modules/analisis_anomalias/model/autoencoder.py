import tensorflow as tf
import numpy as np
from typing import Tuple, List
import logging

class TrafficAutoencoder:
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.logger = logging.getLogger('analisis_anomalias.autoencoder')
        
        # Crear modelo
        self.model = self._build_model()
        self.threshold = None
    
    def _build_model(self) -> tf.keras.Model:
        """Construye el modelo del autoencoder."""
        # Encoder
        input_layer = tf.keras.layers.Input(shape=(self.input_dim,))
        
        # Capas de codificación con regularización
        encoded = tf.keras.layers.Dense(
            128, 
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.01)
        )(input_layer)
        
        encoded = tf.keras.layers.Dropout(0.2)(encoded)
        
        encoded = tf.keras.layers.Dense(
            64,
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.01)
        )(encoded)
        
        # Capa de codificación central
        encoded = tf.keras.layers.Dense(
            self.encoding_dim,
            activation='relu',
            name='bottleneck'
        )(encoded)
        
        # Capas de decodificación
        decoded = tf.keras.layers.Dense(
            64,
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.01)
        )(encoded)
        
        decoded = tf.keras.layers.Dropout(0.2)(decoded)
        
        decoded = tf.keras.layers.Dense(
            128,
            activation='relu',
            kernel_regularizer=tf.keras.regularizers.l2(0.01)
        )(decoded)
        
        # Capa de salida
        output_layer = tf.keras.layers.Dense(
            self.input_dim,
            activation='sigmoid'
        )(decoded)
        
        # Crear modelo
        autoencoder = tf.keras.Model(input_layer, output_layer)
        
        # Compilar modelo
        autoencoder.compile(
            optimizer='adam',
            loss='mean_squared_error',
            metrics=['mae']
        )
        
        return autoencoder
    
    def train(self, X_train: np.ndarray, X_val: np.ndarray, 
             batch_size: int = 32, epochs: int = 100) -> tf.keras.callbacks.History:
        """Entrena el autoencoder con los datos proporcionados."""
        try:
            # Early stopping para evitar overfitting
            early_stopping = tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
            
            # Reducción de learning rate si el entrenamiento se estanca
            reduce_lr = tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.2,
                patience=5,
                min_lr=1e-6
            )
            
            # Entrenar modelo
            history = self.model.fit(
                X_train, X_train,
                epochs=epochs,
                batch_size=batch_size,
                validation_data=(X_val, X_val),
                callbacks=[early_stopping, reduce_lr],
                verbose=1
            )
            
            # Calcular umbral de anomalía basado en el conjunto de validación
            self._calculate_threshold(X_val)
            
            return history
            
        except Exception as e:
            self.logger.error(f"Error durante el entrenamiento: {str(e)}")
            raise
    
    def _calculate_threshold(self, X_val: np.ndarray, percentile: float = 95):
        """Calcula el umbral de error para detección de anomalías."""
        try:
            # Obtener reconstrucciones del conjunto de validación
            reconstructions = self.model.predict(X_val)
            
            # Calcular errores de reconstrucción
            mse = np.mean(np.power(X_val - reconstructions, 2), axis=1)
            
            # Establecer umbral en el percentil especificado
            self.threshold = np.percentile(mse, percentile)
            
            self.logger.info(f"Umbral de anomalía calculado: {self.threshold}")
            
        except Exception as e:
            self.logger.error(f"Error calculando umbral: {str(e)}")
            raise
    
    def detect_anomalies(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detecta anomalías en los datos proporcionados.
        Retorna (is_anomaly, anomaly_scores).
        """
        if self.threshold is None:
            raise ValueError("El modelo debe ser entrenado antes de detectar anomalías")
        
        try:
            # Obtener reconstrucciones
            reconstructions = self.model.predict(X)
            
            # Calcular errores de reconstrucción
            mse = np.mean(np.power(X - reconstructions, 2), axis=1)
            
            # Determinar anomalías
            is_anomaly = mse > self.threshold
            
            # Normalizar scores para facilitar interpretación
            anomaly_scores = mse / self.threshold
            
            return is_anomaly, anomaly_scores
            
        except Exception as e:
            self.logger.error(f"Error detectando anomalías: {str(e)}")
            raise
    
    def save_model(self, path: str):
        """Guarda el modelo entrenado."""
        try:
            self.model.save(path)
            # Guardar también el umbral
            np.save(f"{path}_threshold.npy", self.threshold)
            self.logger.info(f"Modelo guardado en {path}")
        except Exception as e:
            self.logger.error(f"Error guardando modelo: {str(e)}")
            raise
    
    def load_model(self, path: str):
        """Carga un modelo previamente guardado."""
        try:
            self.model = tf.keras.models.load_model(path)
            # Cargar umbral
            self.threshold = np.load(f"{path}_threshold.npy")
            self.logger.info(f"Modelo cargado desde {path}")
        except Exception as e:
            self.logger.error(f"Error cargando modelo: {str(e)}")
            raise
    
    def get_feature_importance(self, X: np.ndarray) -> np.ndarray:
        """
        Calcula la importancia de cada característica basada en el error 
        de reconstrucción por dimensión.
        """
        try:
            reconstructions = self.model.predict(X)
            feature_errors = np.mean(np.abs(X - reconstructions), axis=0)
            
            # Normalizar importancias
            feature_importance = feature_errors / np.sum(feature_errors)
            
            return feature_importance
            
        except Exception as e:
            self.logger.error(f"Error calculando importancia de características: {str(e)}")
            raise