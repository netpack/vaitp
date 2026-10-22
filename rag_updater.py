"""
RAG Index Updater for VAITP Framework.

Pulls the latest vulnerability data from the MySQL database at netpack.pt/vaitp,
regenerates embeddings, and rebuilds the FAISS index used by the RAG component.

Usage:
    - Integrated: called automatically by main_orchestrator.py on startup
      (disable with --no-rag-update)
    - Standalone: python rag_updater.py [--force]
"""

import os
import sys
import logging
import time
import numpy as np
import pandas as pd
import faiss

logger = logging.getLogger(__name__)

# --- Configuration ---
# Database credentials (from environment or defaults)
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_USER = os.environ.get("MYSQL_USER", "vaitp_user")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "vaitp")

# Paths (relative to VAITP_PATH)
VAITP_PATH = os.path.dirname(os.path.abspath(__file__))
FAISS_INDEX_PATH = os.path.join(VAITP_PATH, "index.faiss")
CLEANED_CSV_PATH = os.path.join(VAITP_PATH, "cleaned_python_vulnerabilities.csv")
RAW_CSV_PATH = os.path.join(VAITP_PATH, "python_vulnerabilities.csv")

EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"


def _get_db_record_count() -> int:
    """Query the database to get the current number of Python vulnerability records."""
    try:
        import pymysql
        connection = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DATABASE,
            connect_timeout=10,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM `python_vulnerabilities` WHERE Ignored=0 AND isPython=1")
                count = cursor.fetchone()[0]
                return count
        finally:
            connection.close()
    except Exception as e:
        logger.warning(f"Could not query database for record count: {e}")
        return -1


def _get_local_record_count() -> int:
    """Get the number of records in the local cleaned CSV."""
    if not os.path.isfile(CLEANED_CSV_PATH):
        return 0
    try:
        df = pd.read_csv(CLEANED_CSV_PATH)
        return len(df)
    except Exception:
        return 0


def needs_update(force: bool = False) -> bool:
    """
    Check whether the local FAISS index needs updating.
    Returns True if:
      - force=True
      - FAISS index doesn't exist
      - Database has more records than local CSV
    """
    if force:
        logger.info("RAG update forced by user.")
        return True

    if not os.path.isfile(FAISS_INDEX_PATH):
        logger.info("FAISS index not found locally — update needed.")
        return True

    db_count = _get_db_record_count()
    if db_count < 0:
        # Can't reach DB, skip update
        logger.info("Cannot reach database — skipping RAG update check.")
        return False

    local_count = _get_local_record_count()
    if db_count > local_count:
        logger.info(f"Database has {db_count} records vs {local_count} local — update needed.")
        return True

    logger.info(f"RAG index is up-to-date ({local_count} records).")
    return False


def export_data_from_mysql() -> pd.DataFrame:
    """Export python_vulnerabilities table from MySQL to a DataFrame and save as CSV."""
    import pymysql

    logger.info(f"Connecting to MySQL at {MYSQL_HOST}...")
    connection = pymysql.connect(
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        connect_timeout=15,
    )
    try:
        query = "SELECT * FROM `python_vulnerabilities` WHERE Ignored=0 AND isPython=1;"
        df = pd.read_sql(query, connection)
        df.to_csv(RAW_CSV_PATH, index=False)
        logger.info(f"Exported {len(df)} records to {RAW_CSV_PATH}")
        return df
    finally:
        connection.close()


def clean_and_prepare_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean and normalize the data for embedding generation."""
    df.fillna("Unknown", inplace=True)
    df.to_csv(CLEANED_CSV_PATH, index=False)
    logger.info(f"Cleaned data saved to {CLEANED_CSV_PATH} ({len(df)} records)")
    return df


def combine_fields(row) -> str:
    """Combine relevant fields into a single string for embedding."""
    return f"CVE ID: {row.get('CVE', 'Unknown')} " + str(row.get("VulnerabilityLongDescription", "Unknown"))


def generate_embeddings(df: pd.DataFrame) -> np.ndarray:
    """Generate sentence embeddings for all records."""
    from sentence_transformers import SentenceTransformer

    logger.info(f"Loading embedding model: {EMBEDDING_MODEL_NAME}")
    model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    texts = df.apply(combine_fields, axis=1).tolist()
    logger.info(f"Generating embeddings for {len(texts)} records...")
    embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=True)

    return embeddings


def build_faiss_index(embeddings: np.ndarray) -> None:
    """Normalize embeddings and build/save the FAISS index."""
    faiss.normalize_L2(embeddings)
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)
    faiss.write_index(index, FAISS_INDEX_PATH)
    logger.info(f"FAISS index saved to {FAISS_INDEX_PATH} ({index.ntotal} vectors, dim={dimension})")


def update_rag_index(force: bool = False) -> bool:
    """
    Full RAG update pipeline:
      1. Check if update is needed
      2. Export data from MySQL
      3. Clean data
      4. Generate embeddings
      5. Build FAISS index

    Returns True if update was performed, False if skipped.
    """
    if not needs_update(force=force):
        return False

    start_time = time.time()
    logger.info("=" * 60)
    logger.info("Starting RAG index update from netpack.pt database...")
    logger.info("=" * 60)

    try:
        # Step 1: Export from MySQL
        df = export_data_from_mysql()

        # Step 2: Clean data
        df = clean_and_prepare_data(df)

        # Step 3: Generate embeddings
        embeddings = generate_embeddings(df)

        # Step 4: Build FAISS index
        build_faiss_index(embeddings)

        elapsed = time.time() - start_time
        logger.info(f"RAG index update completed in {elapsed:.1f}s ({len(df)} records)")
        return True

    except ImportError as e:
        logger.warning(
            f"RAG update skipped — missing dependency: {e}. "
            "Install pymysql and sentence-transformers to enable RAG updates."
        )
        return False
    except Exception as e:
        logger.error(f"RAG update failed: {e}")
        logger.info("Continuing with existing FAISS index (if available).")
        return False


# --- Standalone execution ---
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="Update VAITP RAG FAISS index from MySQL database")
    parser.add_argument("--force", action="store_true", help="Force update even if index appears current")
    args = parser.parse_args()

    success = update_rag_index(force=args.force)
    sys.exit(0 if success else 1)
