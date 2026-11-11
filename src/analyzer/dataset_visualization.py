
import os
import pandas as pd
import matplotlib.pyplot as plt

DATASET_FILE = "data/metrics/traffic_features.csv"
OUTPUT_DIR = "data/metrics"

df = pd.read_csv(DATASET_FILE)

os.makedirs(OUTPUT_DIR, exist_ok=True)

features = [
    ("packet_count", "Packet Count Comparison"),
    ("unique_destination_ports", "Unique Destination Ports Comparison"),
]

for column, title in features:
    comparison = df.groupby("label")[column].mean()

    plt.figure(figsize=(7, 4))

    comparison.plot(kind="bar")

    plt.title(title)
    plt.xlabel("Traffic Label")
    plt.ylabel(column.replace("_", " ").title())
    plt.xticks(rotation=0)

    plt.tight_layout()

    output_file = os.path.join(
        OUTPUT_DIR,
        f"{column}_comparison.png"
    )

    plt.savefig(output_file, dpi=150)
    plt.close()

    print(f"Graph saved: {output_file}")

print("\nVisualization completed!")
