import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
import tensorflow as tf
from tensorflow.keras import layers, models

# putting normal as 0 and attack as 1

# Step 1: Load the dataset
data = pd.read_csv('/Users/architanant/Documents/HAWKS/datasets/collection_dataset.csv')

# Step 2: Preprocess the data
# Convert IP address columns to count of unique IPs for simplicity
data['source_ip_count'] = data['source_ips'].apply(lambda x: len(set(x.split(','))))
data['destination_ip_count'] = data['destination_ips'].apply(lambda x: len(set(x.split(','))))

# Encode protocols as a categorical feature by counting the number of protocols
data['protocol_count'] = data['protocols'].apply(lambda x: len(set(x.split(','))))

# Drop original IP address and protocol columns as we've extracted features from them
data = data.drop(['source_ips', 'destination_ips', 'protocols'], axis=1)

# Encode the label column
# label_encoder = LabelEncoder()
# data['label'] = label_encoder.fit_transform(data['label'])  # Normal -> 0, Attack -> 1

# Step 3: Split the data into features and labels
X = data.drop('label', axis=1)
y = data['label']

# Step 4: Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 5: Normalize the feature data
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)


model = models.Sequential([
    layers.Input(shape=(X_train.shape[1],)),  # Input layer matching number of features
    layers.Dense(16, activation='relu'),  # Hidden layer 1
    layers.Dense(8, activation='relu'),  # Hidden layer 2
    layers.Dense(1, activation='sigmoid')  # Output layer with sigmoid for binary classification
])

# Compile the model
model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
history = model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=20, batch_size=32)

# Evaluate the model
loss, accuracy = model.evaluate(X_test, y_test)
print(f'Test Accuracy: {accuracy:.4f}')

# save the model
model.save('prediction_model.h5')

# load the model for prediction
# model = tf.keras.models.load_model('prediction_model.h5')