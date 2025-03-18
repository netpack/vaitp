from pymatgen.io.cif import CifParser
import argparse

def main():
    arg_parser = argparse.ArgumentParser(description="Process a CIF file with extended logic.")
    arg_parser.add_argument("cif_file", help="Path to the CIF file")
    arg_parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = arg_parser.parse_args()

    if args.verbose:
        print("Verbose mode enabled.")

    # Basic file extension check
    if not args.cif_file.lower().endswith(".cif"):
        print("Error: The provided file does not have a .cif extension.")
        return

    try:
        # Primary parsing (vulnerable call)
        cif_parser = CifParser(args.cif_file)
        structures = cif_parser.parse_structures()
        if args.verbose:
            print("Primary parsing succeeded.")
        for idx, struct in enumerate(structures):
            print(f"Structure {idx}:", struct)
    except Exception as primary_err:
        print("Primary parsing failed:", primary_err)
        # Alternate branch: try a different method (still vulnerable)
        try:
            print("Attempting alternate parsing method.")
            cif_parser = CifParser(args.cif_file)
            structures = cif_parser.get_structures()
            for idx, struct in enumerate(structures):
                print(f"Alternate Structure {idx}:", struct)
        except Exception as alternate_err:
            print("Alternate parsing also failed:", alternate_err)

if __name__ == "__main__":
    main()
