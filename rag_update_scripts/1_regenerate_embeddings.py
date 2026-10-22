import pandas as pd
import faiss
from sentence_transformers import SentenceTransformer

# Load the metadata
metadata = pd.read_csv("cleaned_python_vulnerabilities.csv")

# Load embedding model
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")

def combine_fields(row):
    """
    Combines multiple fields into a single string for embedding generation.
    """
    fields = [
        str(row.get("CVE", "Unknown")),
        str(row.get("Publishdate", "Unknown")),
        str(row.get("VulnerabilityLongDescription", "Unknown")),
        str(row.get("VulnerableCodeSample", "")),
    ]
    return " ".join(fields)


# Check if CVE-2024-23346 exists in the CSV
cve_target = "CVE-2024-23346"
cve_row = metadata[metadata["CVE"] == cve_target]

if cve_row.empty:
    print(f"❌ ERROR: {cve_target} is missing from the CSV!")
else:
    print(f"✅ {cve_target} found in CSV. Proceeding with embedding creation...")

    # Generate embeddings
    all_texts = metadata.apply(combine_fields, axis=1).tolist()
    embeddings = embedding_model.encode(all_texts, convert_to_numpy=True)

    # Save embeddings for debugging
    import numpy as np
    np.save("embeddings.npy", embeddings)

    print("✅ Embeddings generated and saved.")
