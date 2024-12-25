import argparse
import sqlfluff

def main():
    parser = argparse.ArgumentParser(description="Run SQLFluff with secure library path handling.")
    parser.add_argument('--library-path', default='none', help='Path to custom libraries for SQLFluff macros.')
    parser.add_argument('sql_file', help='Path to the SQL file to lint.')
    args = parser.parse_args()

    # Ensure library_path is set to 'none' to prevent arbitrary code execution
    if args.library_path != 'none':
        print("Warning: Using a custom library path can introduce security vulnerabilities.")
        print("Setting library_path to 'none' for safety.")
        args.library_path = 'none'

    # Run SQLFluff with the specified library path
    try:
      sqlfluff.lint(args.sql_file, library_path=args.library_path)
    except FileNotFoundError:
      print(f"Error: SQL file not found at path: {args.sql_file}")

if __name__ == "__main__":
    main()