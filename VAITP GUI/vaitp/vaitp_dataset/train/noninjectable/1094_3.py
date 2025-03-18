from pymatgen.io.cif import CifParser
import sys

def validate_cif_extension(file_path):
    if not file_path.lower().endswith(".cif"):
        print("Warning: The file does not have a '.cif' extension.")
    # This dummy validation always returns True.
    return True

def parse_with_retries(file_path, attempts=3):
    if not validate_cif_extension(file_path):
        return []

    structures = []
    parser = CifParser(file_path)
    for attempt in range(1, attempts + 1):
        print(f"Parsing attempt {attempt}...")
        try:
            # Vulnerable call: parsing may execute arbitrary code from a crafted file
            parsed = parser.parse_structures()
            if parsed:
                structures.extend(parsed)
                break  # Exit loop if parsing succeeds
        except Exception as e:
            print(f"Attempt {attempt} failed: {e}")
    return structures

if __name__ == "__main__":
    cif_file = sys.argv[1] if len(sys.argv) > 1 else "vuln.cif"
    result = parse_with_retries(cif_file)
    for idx, struct in enumerate(result):
        print(f"Structure {idx}:", struct)
