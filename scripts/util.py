import numpy as np
from sklearn.preprocessing import StandardScaler
import pandas as pd
from sklearn.model_selection import train_test_split

def preprocess_sequence_input(input_sequence):
    """
    Preprocess a sequence of input dictionaries for the deep learning model.

    Parameters:
    input_sequence (list): A list of 5 dictionaries, each representing a single row of input with keys corresponding to the CSV headers.

    Returns:
    numpy array: Processed feature vector suitable for model input with shape (5, num_features).
    """
    data = pd.read_csv('./datasets/collection_dataset-M.csv')
    data['source_ip_count'] = data['source_ips'].apply(lambda x: len(set(x.split(','))))
    data['destination_ip_count'] = data['destination_ips'].apply(lambda x: len(set(x.split(','))))
    data['protocol_count'] = data['protocols'].apply(lambda x: len(set(x.split(','))))
    data = data.drop(['source_ips', 'destination_ips', 'protocols'], axis=1)

    X = data.drop('label', axis=1)
    y = data['label']
    X_normal = X[y == 0]

    X_train, X_test = train_test_split(X_normal, test_size=0.2, random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    processed_features = []

    for input_row in input_sequence:
        # Step 1: Extract features from input row
        source_ips = input_row['source_ips']
        destination_ips = input_row['destination_ips']
        time_variance = input_row['time_variance']
        max_occuring_byte_size = input_row['max_occuring_byte_size']
        byte_size_variance = input_row['byte_size_variance']
        protocols = input_row['protocols']
        number_of_packets = input_row['number_of_packets']

        # Step 2: Process IP addresses (extract the count of unique IPs)
        source_ip_count = len(set(source_ips.split(','))) if isinstance(source_ips, str) else 0
        destination_ip_count = len(set(destination_ips.split(','))) if isinstance(destination_ips, str) else 0

        # Step 3: Process protocols (count the number of unique protocols)
        protocol_count = len(set(protocols.split(','))) if isinstance(protocols, str) else 0

        # Step 4: Create a feature vector with all numerical values
        features = np.array([
            source_ip_count,        # Count of unique source IPs
            destination_ip_count,   # Count of unique destination IPs
            time_variance,          # Time variance between packets
            max_occuring_byte_size, # Maximum occurring byte size
            byte_size_variance,     # Variance of byte sizes
            protocol_count,         # Count of unique protocols
            number_of_packets       # Number of packets observed
        ])

        # Append the features to the list
        processed_features.append(features)

    # Convert to numpy array of shape (5, num_features)
    processed_features = np.array(processed_features)

    # Step 5: Normalize the feature values using the global scaler
    # Assuming `scaler` is already fitted using the training data
    normalized_features = scaler.transform(processed_features)

    return normalized_features