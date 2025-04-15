try:
    import tensorflow as tf
except ImportError:
    print("TensorFlow not found. Please install required packages: pip install -r requirements.txt")
    raise

from typing import List, Dict

class Autoencoder(tf.keras.Model):
    def __init__(self, input_dim: int, encoding_dims: List[int]):
        super(Autoencoder, self).__init__()
        
        # Encoder layers
        self.encoder = tf.keras.Sequential()
        for dim in encoding_dims:
            self.encoder.add(tf.keras.layers.Dense(dim, activation='relu'))
        
        # Decoder layers (reverse of encoder)
        self.decoder = tf.keras.Sequential()
        for dim in reversed(encoding_dims[:-1]):
            self.decoder.add(tf.keras.layers.Dense(dim, activation='relu'))
        self.decoder.add(tf.keras.layers.Dense(input_dim, activation='sigmoid'))
    
    def call(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def create_autoencoder(config: Dict) -> Autoencoder:
    """Crea y configura un modelo autoencoder."""
    input_dim = len(config.get('feature_columns', []))
    encoding_dims = config.get('encoding_dims', [32, 16, 8])
    
    model = Autoencoder(input_dim, encoding_dims)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='mse'
    )
    
    return model