import csv

def safe_load_csv(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        data = []
        for row in reader:
            # Ensure that the row does not contain any executable code
            if any('eval' in cell for cell in row):
                raise ValueError("Malicious content detected in CSV.")
            data.append(row)
    return data

# Example usage
try:
    csv_data = safe_load_csv('malicious_file.csv')
except ValueError as e:
    print(e)