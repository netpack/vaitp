import argparse
import sqlfluff

def main():
    parser = argparse.ArgumentParser(description="Run SQLFluff with secure library path handling.")
    parser.add_argument('--library-path', default='none', help='Path to custom libraries for SQLFluff macros.')
    args = parser.parse_args()

    # Ensure library_path is set to 'none' to prevent arbitrary code execution
    if args.library_path != 'none':
        print("Warning: Using a custom library path can introduce security vulnerabilities.")
        print("Setting library_path to 'none' for safety.")
        args.library_path = 'none'

    # Run SQLFluff with the specified library path
    sqlfluff.lint("your_sql_file.sql", library_path=args.library_path)

if __name__ == "__main__":
    main()