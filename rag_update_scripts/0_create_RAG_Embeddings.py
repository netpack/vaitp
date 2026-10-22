import os
import pandas as pd
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import pymysql

# File paths
CSV_PATH = 'python_vulnerabilities.csv'
CLEANED_CSV_PATH = 'cleaned_python_vulnerabilities.csv'
FAISS_INDEX_PATH = 'index.faiss'
EMBEDDINGS_MODEL = 'all-MiniLM-L6-v2'


# Load database credentials from environment variables
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "vaitp")
MYSQL_USER = os.environ.get("MYSQL_USER", "vaitp_user")
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")



def export_data_to_csv():
    """
    Exports the python_vulnerabilities table from the MySQL database to a CSV file.
    """
    try:
        connection = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE
        )

        query = "SELECT * FROM `python_vulnerabilities` where Ignored=0 AND isPython=1;"
        df = pd.read_sql(query, connection)
        df.to_csv(CSV_PATH, index=False)
        print(f"Data exported to {CSV_PATH}")

    except Exception as e:
        print(f"Error exporting data: {e}")
    finally:
        if connection:
            connection.close()


def clean_and_prepare_data():
    """
    Cleans and normalizes the data for embedding generation.
    """
    try:
        df = pd.read_csv(CSV_PATH)

        # Fill missing values with placeholders
        df.fillna("Unknown", inplace=True)

        # Save the cleaned data to a new CSV file
        df.to_csv(CLEANED_CSV_PATH, index=False)
        print(f"Cleaned data saved to {CLEANED_CSV_PATH}")

        return df

    except Exception as e:
        print(f"Error cleaning data: {e}")
        exit(1)


def combine_fields(row):
    return f"CVE ID: {row.get('CVE', 'Unknown')} " + str(row.get("VulnerabilityLongDescription", "Unknown"))



def generate_embeddings():
    """
    Generates embeddings for combined fields and saves the results.
    """
    try:
        df = pd.read_csv(CLEANED_CSV_PATH)
        model = SentenceTransformer(EMBEDDINGS_MODEL)

        # Combine fields into a single string
        df['combined_text'] = df.apply(combine_fields, axis=1)

        # Generate embeddings
        print("Generating embeddings...")
        embeddings = df['combined_text'].apply(lambda x: model.encode(x))

        # Convert embeddings to a NumPy array
        embeddings_matrix = np.vstack(embeddings.values)



        # Save embeddings as a JSON file for reference
        df['embedding'] = embeddings.tolist()
        df.to_json(CLEANED_CSV_PATH.replace('.csv', '_embeddings.json'), orient='records')

        print(f"Embeddings generated and saved.")
        return embeddings_matrix, df
    except Exception as e:
        print(f"Error generating embeddings: {e}")
        exit(1)


def create_faiss_index(embeddings_matrix):
    """
    Creates a FAISS index and saves it.
    """
    try:
        # dimension = embeddings_matrix.shape[1]
        # index = faiss.IndexFlatL2(dimension)
        # index.add(embeddings_matrix)
        # faiss.write_index

        # Normalize the embeddings matrix in place using the correct variable name
        faiss.normalize_L2(embeddings_matrix)
        dimension = embeddings_matrix.shape[1]
        index = faiss.IndexFlatL2(dimension)
        index.add(embeddings_matrix)
        faiss.write_index(index, FAISS_INDEX_PATH)
        print(f"FAISS index created and saved to {FAISS_INDEX_PATH}")

        print(f"FAISS index created and saved to {FAISS_INDEX_PATH}")
    except Exception as e:
        print(f"Error creating FAISS index: {e}")
        exit(1)


if __name__ == "__main__":
    print("Starting the process...")

    # Step 1: Export data from MySQL to CSV
    export_data_to_csv()

    # Step 2: Clean and prepare data
    cleaned_data = clean_and_prepare_data()

    # Step 3: Generate embeddings
    embeddings_matrix, df = generate_embeddings()

    # Step 4: Create FAISS index
    create_faiss_index(embeddings_matrix)

    print("Process completed successfully!")
