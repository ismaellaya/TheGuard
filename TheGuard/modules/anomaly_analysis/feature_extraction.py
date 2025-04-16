import json
import os

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
                        'bytes': flow.get('bytes'),
                        'duration': flow.get('end_time', 0) - flow.get('start_time', 0),
                        'packet_rate': flow.get('packets') / (flow.get('end_time', 1) - flow.get('start_time', 1))
                    }
                    flow_features.append(features)
            except (json.JSONDecodeError, ZeroDivisionError):
                continue

    with open(output_path, 'w') as output_file:
        json.dump(flow_features, output_file, indent=4)

    print(f"Flow features extracted and saved to {output_path}")