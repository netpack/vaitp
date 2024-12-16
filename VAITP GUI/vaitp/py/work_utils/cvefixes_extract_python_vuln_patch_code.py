import sqlite3, os, importlib, sys, re

def load_external_module(module_path, module_name):
    """
    Dynamically load a module from the given path.
    """
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def extract_code_for_cve(db_path, cve_id):
    """
    Extracts vulnerable and patched code snippets for a given CVE from an SQLite database.

    Args:
        db_path (str): The path to the SQLite database file.
        cve_id (str): The CVE identifier (e.g., "CVE-2021-23385").

    Returns:
        list: A list of dictionaries, each containing:
            'vulnerable_code': str
            'patched_code': str
        Returns an empty list if no matching data is found.
    """

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT code_before, code_after
            FROM file_change
            WHERE hash = (SELECT hash from fixes where cve_id = ?)
            """,
            (cve_id,)
        )

        results = cursor.fetchall()


        extracted_data = []
        if results:
            for row in results:
                patch_before, patch_after = row
                extracted_data.append(
                    {
                        'vulnerable_code': patch_before,
                        'patched_code': patch_after,
                    }
                )

        conn.close()
        return extracted_data

    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        return []

def get_next_filename(directory, base_filename):
    """
    Finds the next available filename in a directory using the specified naming convention.
    """
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    
    pattern = re.compile(f"^{base_filename}_(\\d+)\\.py$")
    
    existing_numbers = []
    for filename in files:
        match = pattern.match(filename)
        if match:
            existing_numbers.append(int(match.group(1)))
    
    if not existing_numbers:
        return f"{base_filename}_1.py"
    else:
        max_number = max(existing_numbers)
        return f"{base_filename}_{max_number + 1}.py"


if __name__ == "__main__":
    db_file = "/Users/fredericbogaerts/CVEfixes_v1.0.8/Data/CVEfixes.db"
    injectable_dir = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/injectable/"
    noninjectable_dir = "/Users/fredericbogaerts/vaitp/VAITP GUI/vaitp/vaitp_dataset/train/noninjectable/"

    if not os.path.exists(db_file):
      print(f"Error: Database file '{db_file}' not found.")
    else:
        if not os.path.exists(injectable_dir):
            os.makedirs(injectable_dir)

        if not os.path.exists(noninjectable_dir):
            os.makedirs(noninjectable_dir)


        vaitp_db = load_external_module("../scrappers/0_vaitp_db.py","vaitp_db")

        rows = vaitp_db.execute_query("SELECT id, CVE FROM python_vulnerabilities")

        # Process each row
        for row in rows:
            
            vuln_id = row[0]
            cve_to_extract = row[1]
            
            print(f"Processing CVE: {cve_to_extract}")
            
            code_data = extract_code_for_cve(db_file, cve_to_extract)

            if code_data:
                for i, item in enumerate(code_data):

                    base_filename = str(vuln_id)
                    
                    # Save patched code
                    patched_filename = get_next_filename(injectable_dir, base_filename)
                    patched_filepath = os.path.join(injectable_dir, patched_filename)
                    with open(patched_filepath, "w") as f:
                         f.write(item['patched_code'])
                    print(f"Saved patched code to: {patched_filepath}")

                    # Save vulnerable code
                    vulnerable_filename = get_next_filename(noninjectable_dir, base_filename)
                    vulnerable_filepath = os.path.join(noninjectable_dir, vulnerable_filename)
                    with open(vulnerable_filepath, "w") as f:
                        f.write(item['vulnerable_code'])
                    print(f"Saved vulnerable code to: {vulnerable_filepath}")
                    
            else:
                print(f"No data found for CVE: {cve_to_extract}")