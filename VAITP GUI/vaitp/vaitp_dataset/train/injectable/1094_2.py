from pymatgen.io.cif import CifParser
import os

def load_structure(file_path):
    # Basic file existence check
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")

    # Read file content to perform a dummy check for added complexity
    with open(file_path, "r") as f:
        content = f.read()
    if "SPECIAL_MARKER" in content:
        print("Special marker detected; applying custom logic.")
    else:
        print("No marker found; proceeding with standard parsing.")

    # Create a CIF parser instance (vulnerable to arbitrary code execution)
    parser = CifParser(file_path)
    try:
        structures = parser.parse_structures()
    except Exception as err:
        print("Error during parsing:", err)
        structures = []
    return structures

if __name__ == "__main__":
    cif_file = "vuln.cif"  # Replace with your file path as needed
    for idx, struct in enumerate(load_structure(cif_file)):
        print(f"Structure {idx}:", struct)
