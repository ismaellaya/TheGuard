import json
import numpy as np
import pandas as pd
from .model import AnomalyDetectionModel
from .feature_extraction import extract_flow_features

def train_with_suricata_logs(model, suricata_log_path, labels_path):
    """
    Train the model using flow features extracted from Suricata logs.

    Args:
        model (AnomalyDetectionModel): The anomaly detection model.
        suricata_log_path (str): Path to the Suricata log file.
        labels_path (str): Path to the labels file (JSON format).
    """
    flow_features_path = "./logs/flow_features.json"
    extract_flow_features(suricata_log_path, flow_features_path)

    with open(flow_features_path, 'r') as features_file:
        flow_features = json.load(features_file)

    with open(labels_path, 'r') as labels_file:
        labels = json.load(labels_file)

    data = np.array([
        [
            feature['packets'],
            feature['bytes'],
            feature['duration'],
            feature['packet_rate']
        ] for feature in flow_features
    ])

    model.fine_tune(data)
    model.save_model()

def train_with_public_dataset(model, dataset_path, label_column):
    """
    Train the model using a public dataset (e.g., CICIDS2017 or NSL-KDD).

    Args:
        model (AnomalyDetectionModel): The anomaly detection model.
        dataset_path (str): Path to the dataset file (CSV format).
        label_column (str): Name of the column containing labels.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    dataset = pd.read_csv(dataset_path)
    labels = dataset[label_column].values
    features = dataset.drop(columns=[label_column]).values

    model.fine_tune(features, labels)
    model.save_model()

def infer_from_suricata_logs(model, suricata_log_path):
    """
    Perform inference on flow features extracted from Suricata logs.

    Args:
        model (AnomalyDetectionModel): The anomaly detection model.
        suricata_log_path (str): Path to the Suricata log file.

    Returns:
        List[Dict]: List of anomalies detected.
    """
    flow_features_path = "./logs/flow_features_inference.json"
    extract_flow_features(suricata_log_path, flow_features_path)

    with open(flow_features_path, 'r') as features_file:
        flow_features = json.load(features_file)

    data = np.array([
        [
            feature['packets'],
            feature['bytes'],
            feature['duration'],
            feature['packet_rate']
        ] for feature in flow_features
    ])

    predictions = model.infer(data)
    anomalies = [flow_features[i] for i in range(len(predictions)) if predictions[i] == -1]

    return anomalies

def evaluate_model(model, test_data, test_labels):
    """
    Evaluate the model's performance on a test dataset.

    Args:
        model (AnomalyDetectionModel): The anomaly detection model.
        test_data (np.ndarray): Test dataset features.
        test_labels (np.ndarray): True labels for the test dataset.

    Returns:
        Dict: Evaluation metrics such as accuracy, precision, recall, and F1-score.
    """
    from sklearn.metrics import classification_report

    predictions = model.infer(test_data)
    report = classification_report(test_labels, predictions, output_dict=True)
    return report