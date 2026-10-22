import pandas as pd
import numpy as np

CSV_PATH = "cleaned_python_vulnerabilities.csv"
EMBEDDINGS_PATH = "embeddings.npy"

# Load the CSV
df = pd.read_csv(CSV_PATH)

# Find the row for CVE-2024-23346
cve_row = df[df["CVE"] == "CVE-2024-23346"]

if cve_row.empty:
    print("❌ CVE-2024-23346 NOT found in CSV!")
else:
    print("✅ CVE-2024-23346 found in CSV.")

# Load the embeddings
embeddings = np.load(EMBEDDINGS_PATH)

# Check number of embeddings vs. CSV rows
if len(embeddings) != len(df):
    print(f"⚠️ Mismatch: {len(df)} CVEs, but {len(embeddings)} embeddings!")
else:
    print(f"✅ {len(embeddings)} embeddings match CSV rows.")

# Find index of CVE-2024-23346
index = cve_row.index[0]
if index >= len(embeddings):
    print("❌ No embedding found for CVE-2024-23346!")
else:
    print(f"✅ Found embedding for CVE-2024-23346 at index {index}.")
    print(f"🔢 Embedding vector (first 5 values): {embeddings[index][:5]}")
