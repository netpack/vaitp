# Normalize embeddings
faiss.normalize_L2(embeddings)

# Create FAISS index
dimension = embeddings.shape[1]
faiss_index = faiss.IndexFlatL2(dimension)
faiss_index.add(embeddings)

# Save the new FAISS index
faiss.write_index(faiss_index, "index.faiss")

print("✅ FAISS index rebuilt and saved.")
