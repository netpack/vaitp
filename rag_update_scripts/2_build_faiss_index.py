import faiss
import numpy as np
import pandas as pd

# Load CSV and embeddings
metadata = pd.read_csv('cleaned_python_vulnerabilities.csv')
embeddings = np.load('embeddings.npy')

# Normalize embeddings (if not already done)
faiss.normalize_L2(embeddings)

# Initialize FAISS index (you can use the appropriate index type for your data)
index = faiss.IndexFlatL2(embeddings.shape[1])

# Add metadata (CVE IDs) to the FAISS index
index.add(embeddings)

# Save the FAISS index
faiss.write_index(index, 'index.faiss')

# Store the mapping from FAISS index to CVE IDs for later retrieval
np.save('cve_index_mapping.npy', metadata["CVE"].values)

print("✅ FAISS index successfully built and saved!")
