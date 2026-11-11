
import pandas as pd

DATASET_FILE = "data/metrics/traffic_features.csv"

# Membaca dataset
df = pd.read_csv(DATASET_FILE)

# Informasi dasar dataset
print("Dataset Information")
print("-" * 40)
print(f"Total samples: {len(df)}")
print(f"Total features: {len(df.columns)}")
print(f"Shape: {df.shape}")

# Melihat isi dataset
print("\nDataset Preview")
print(df.to_string(index=False))

# Statistik setiap fitur numerik
print("\nStatistical Summary")
print(df.describe().to_string())

# Membandingkan fitur berdasarkan label
print("\nComparison by Traffic Label")

features = [
    "packet_count",
    "byte_count",
    "tcp_count",
    "client_packets",
    "server_packets",
    "unique_destination_ports"
]

comparison = df.groupby("label")[features].mean()

print(comparison.to_string())
