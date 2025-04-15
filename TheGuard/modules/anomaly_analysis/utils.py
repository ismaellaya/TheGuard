try:
    import numpy as np
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print("Required dependencies not found. Please install required packages: pip install -r requirements.txt")
    raise

from typing import Dict

_scaler = StandardScaler()

def normalize_data(data: np.ndarray) -> np.ndarray:
    """Normaliza los datos usando StandardScaler."""
    if len(data.shape) == 1:
        data = data.reshape(1, -1)
    return _scaler.fit_transform(data)

def extract_features(connection_data: Dict) -> Dict:
    """Extrae características relevantes de los datos de conexión."""
    duration = (connection_data.get('last_seen', 0) - 
               connection_data.get('first_seen', 0)).total_seconds()
    
    features = {
        'packets_per_second': connection_data.get('packets', 0) / max(duration, 1),
        'bytes_per_second': connection_data.get('bytes', 0) / max(duration, 1),
        'unique_ports': len(connection_data.get('ports', set())),
        'connection_duration': duration,
        'protocol_type': _encode_protocol(connection_data.get('protocol', '')),
        'tcp_flags': _encode_tcp_flags(connection_data.get('tcp_flags', 0)),
        'packet_size_mean': connection_data.get('packet_size_mean', 0),
        'packet_size_std': connection_data.get('packet_size_std', 0)
    }
    
    return features

def _encode_protocol(protocol: str) -> float:
    """Codifica el protocolo como valor numérico."""
    protocols = {'tcp': 1.0, 'udp': 2.0, 'icmp': 3.0}
    return protocols.get(protocol.lower(), 0.0)

def _encode_tcp_flags(flags: int) -> float:
    """Codifica los flags TCP como valor numérico normalizado."""
    return float(flags) / 255  # Normalizar a [0,1]

def calculate_anomaly_score(reconstruction_error: float, threshold: float) -> float:
    """Calcula el score de anomalía basado en el error de reconstrucción."""
    return reconstruction_error / threshold if threshold > 0 else reconstruction_error