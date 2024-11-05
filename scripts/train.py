import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, LayerNormalization, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.layers import MultiHeadAttention, GlobalAveragePooling1D


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
X_test = scaler.transform(X_test)

input_dim = X_train.shape[1]
print(input_dim)

sequence_length = 10
num_features = X_train.shape[1]  # should be 7 based on your dataset

num_samples = len(X_train)
num_sequences = num_samples // sequence_length

X_train = np.array([X_train[i:i + sequence_length] for i in range(0, num_samples - sequence_length + 1, sequence_length)])

@tf.keras.utils.register_keras_serializable()
class TransformerBlock(tf.keras.layers.Layer):
    def __init__(self, embed_dim, num_heads, ff_dim, rate=0.1,**kwargs):
        super(TransformerBlock, self).__init__(**kwargs)
        self.att = MultiHeadAttention(num_heads=num_heads, key_dim=embed_dim)
        self.ffn = tf.keras.Sequential(
            [Dense(ff_dim, activation="relu"), Dense(embed_dim)]
        )
        self.layernorm1 = LayerNormalization(epsilon=1e-6)
        self.layernorm2 = LayerNormalization(epsilon=1e-6)
        self.dropout1 = Dropout(rate)
        self.dropout2 = Dropout(rate)

    def call(self, inputs, training):
        attn_output = self.att(inputs, inputs)
        attn_output = self.dropout1(attn_output, training=training)
        out1 = self.layernorm1(inputs + attn_output)
        ffn_output = self.ffn(out1)
        ffn_output = self.dropout2(ffn_output, training=training)
        return self.layernorm2(out1 + ffn_output)


def create_dos_prediction_model(sequence_length, num_features, embed_dim, num_heads, ff_dim, num_layers):
    inputs = Input(shape=(sequence_length, num_features))
    x = Dense(embed_dim)(inputs)

    # Add Transformer Blocks
    for _ in range(num_layers):
        x = TransformerBlock(embed_dim, num_heads, ff_dim)(x,training=True)

    # Global pooling and output layer
    x = GlobalAveragePooling1D()(x)
    outputs = Dense(1, activation="sigmoid")(x)

    model = Model(inputs=inputs, outputs=outputs)
    return model

def start_train():
# Parameters
    sequence_length = 10    # example sequence length, tune based on data
    num_features = 7        # number of features in your data
    embed_dim = 64          # embedding dimensions
    num_heads = 4           # number of attention heads
    ff_dim = 128            # feed-forward network dimension
    num_layers = 2          # number of transformer blocks

    # Model Instantiation
    model = create_dos_prediction_model(sequence_length, num_features, embed_dim, num_heads, ff_dim, num_layers)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    model.summary()

    model.fit(X_train, y, epochs=10, batch_size=32, validation_split=0.2)
    model.save('prediction_model.keras')


# start_train()