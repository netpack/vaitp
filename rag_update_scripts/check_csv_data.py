import pandas as pd

# Load the metadata CSV
metadata = pd.read_csv("cleaned_python_vulnerabilities.csv")

# Check if CVE-2024-23346 exists
cve_query = "CVE-2024-23346"
matching_rows = metadata[metadata["CVE"].astype(str) == cve_query]

if not matching_rows.empty:
    print("CVE Found in CSV:")
    print(matching_rows)
else:
    print(f"{cve_query} is NOT in the CSV! Check your data preprocessing.")
