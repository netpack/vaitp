import faiss
import numpy as np

# Load the FAISS index
index = faiss.read_index("index.faiss")

# Load the CVE ID mapping
cve_mapping = np.load("cve_index_mapping.npy", allow_pickle=True)

# Load the embeddings (to perform the search)
embeddings = np.load("embeddings.npy")

# The CVE (ensure it's an updated one..)
query_cve = "CVE-2025-27105"

# Find the row index for the CVE in the CSV
query_index = np.where(cve_mapping == query_cve)[0][0]
query_embedding = embeddings[query_index].reshape(1, -1)

# Perform the search in FAISS
k = 5  # Retrieve top 5 results
distances, indices = index.search(query_embedding, k)

print(f"Searching FAISS for {query_cve}...")

# Display the results
for i in range(k):
    found_cve = cve_mapping[indices[0][i]]
    distance = distances[0][i]
    print(f"Found CVE: {found_cve}, Distance: {distance}")
