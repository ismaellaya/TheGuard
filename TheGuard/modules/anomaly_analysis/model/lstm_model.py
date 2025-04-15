try:
    import tensorflow as tf
except ImportError:
    print("TensorFlow not found. Please install required packages: pip install -r requirements.txt")
    raise

from typing import List, Dict

class LSTMAutoencoder(tf.keras.Model):
    def __init__(self, timesteps: int, features: int, latent_dim: int):
        super(LSTMAutoencoder, self).__init__()
        
        # Encoder
        self.encoder = tf.keras.Sequential([
            tf.keras.layers.LSTM(64, activation='relu', 
                               input_shape=(timesteps, features),
                               return_sequences=True),
            tf.keras.layers.LSTM(32, activation='relu', 
                               return_sequences=False),
            tf.keras.layers.Dense(latent_dim, activation='relu')
        ])
        
        # Decoder
        self.decoder = tf.keras.Sequential([
            tf.keras.layers.RepeatVector(timesteps),
            tf.keras.layers.LSTM(32, activation='relu', 
                               return_sequences=True),
            tf.keras.layers.LSTM(64, activation='relu', 
                               return_sequences=True),
            tf.keras.layers.TimeDistributed(
                tf.keras.layers.Dense(features, activation='sigmoid')
            )
        ])
    
    def call(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def create_lstm_autoencoder(config: Dict) -> LSTMAutoencoder:
    """Crea y configura un modelo LSTM autoencoder."""
    timesteps = config.get('timesteps', 10)
    features = len(config.get('feature_columns', []))
    latent_dim = config.get('latent_dim', 16)
    
    model = LSTMAutoencoder(timesteps, features, latent_dim)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='mse'
    )
    
    return model