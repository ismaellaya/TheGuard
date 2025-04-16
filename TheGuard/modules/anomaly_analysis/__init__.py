import json
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest

class AnomalyDetectionModel:
    def __init__(self, model_path):
        self.model_path = model_path
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=2)

    def fine_tune(self, data, labels):
        """
        Fine-tune the model with the given data and labels.

        Args:
            data (np.ndarray): The input data for training.
            labels (np.ndarray): The corresponding labels for the data.
        """
        scaled_data = self.scaler.fit_transform(data)
        reduced_data = self.pca.fit_transform(scaled_data)
        self.model.fit(reduced_data)

    def train_with_suricata_logs(self, suricata_log_path, labels_path):
        """
        Train the model using flow features extracted from Suricata logs.

        Args:
            suricata_log_path (str): Path to the Suricata log file.
            labels_path (str): Path to the labels file (JSON format).
        """
        # Extract flow features
        flow_features_path = "./logs/flow_features.json"
        self.extract_flow_features(suricata_log_path, flow_features_path)

        # Load features and labels
        with open(flow_features_path, 'r') as features_file:
            flow_features = json.load(features_file)

        with open(labels_path, 'r') as labels_file:
            labels = json.load(labels_file)

        # Convert features to numpy array
        data = np.array([
            [
                feature['packets'],
                feature['bytes']
            ] for feature in flow_features
        ])

        # Train the model
        self.fine_tune(data, np.array(labels))

    def train_with_public_dataset(self, dataset_path, label_column):
        """
        Train the model using a public dataset (e.g., CICIDS2017 or NSL-KDD).

        Args:
            dataset_path (str): Path to the dataset file (CSV format).
            label_column (str): Name of the column containing labels.
        """
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

        # Load dataset
        dataset = pd.read_csv(dataset_path)

        # Extract features and labels
        labels = dataset[label_column].values
        features = dataset.drop(columns=[label_column]).values

        # Train the model
        self.fine_tune(features, labels)

    def infer_from_suricata_logs(self, suricata_log_path):
        """
        Perform inference on flow features extracted from Suricata logs.

        Args:
            suricata_log_path (str): Path to the Suricata log file.

        Returns:
            List[Dict]: List of anomalies detected.
        """
        # Extract flow features
        flow_features_path = "./logs/flow_features_inference.json"
        self.extract_flow_features(suricata_log_path, flow_features_path)

        # Load features
        with open(flow_features_path, 'r') as features_file:
            flow_features = json.load(features_file)

        # Convert features to numpy array
        data = np.array([
            [
                feature['packets'],
                feature['bytes']
            ] for feature in flow_features
        ])

        # Scale and reduce dimensions
        scaled_data = self.scaler.transform(data)
        reduced_data = self.pca.transform(scaled_data)

        # Perform inference
        predictions = self.model.predict(reduced_data)
        anomalies = [flow_features[i] for i in range(len(predictions)) if predictions[i] == -1]

        return anomalies

    @staticmethod
    def extract_flow_features(suricata_log_path, output_path):
        """
        Extract flow-level features from Suricata logs and save them to a JSON file.

        Args:
            suricata_log_path (str): Path to the Suricata log file.
            output_path (str): Path to save the extracted features.
        """
        if not os.path.exists(suricata_log_path):
            raise FileNotFoundError(f"Suricata log file not found: {suricata_log_path}")

        flow_features = []

        with open(suricata_log_path, 'r') as log_file:
            for line in log_file:
                try:
                    log_entry = json.loads(line)
                    if 'flow' in log_entry:
                        flow = log_entry['flow']
                        features = {
                            'src_ip': flow.get('src_ip'),
                            'dest_ip': flow.get('dest_ip'),
                            'src_port': flow.get('src_port'),
                            'dest_port': flow.get('dest_port'),
                            'protocol': flow.get('protocol'),
                            'packets': flow.get('packets'),
                            'bytes': flow.get('bytes')
                        }
                        flow_features.append(features)
                except json.JSONDecodeError:
                    continue

        with open(output_path, 'w') as output_file:
            json.dump(flow_features, output_file, indent=4)

        print(f"Flow features extracted and saved to {output_path}")

# Example usage
if __name__ == "__main__":
    model = AnomalyDetectionModel(model_path="./model/anomaly_model.h5")
    suricata_log_path = "./logs/suricata.log"  # Path to Suricata log file
    labels_path = "./logs/labels.json"  # Path to labels file

    # Train the model with Suricata logs
    model.train_with_suricata_logs(suricata_log_path, labels_path)

    dataset_path = "./datasets/cicids2017.csv"  # Path to public dataset
    label_column = "Label"  # Column containing labels

    # Train the model with a public dataset
    model.train_with_public_dataset(dataset_path, label_column)

    # Perform inference on new Suricata logs
    anomalies = model.infer_from_suricata_logs(suricata_log_path)
    print("Anomalies detected:", anomalies)