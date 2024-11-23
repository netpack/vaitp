import csv

def load_csv_with_eval(file_path):
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            # Vulnerable code that executes arbitrary Python code from the CSV
            eval(row[0])  # Assuming the first cell contains the code to execute

# Example usage
load_csv_with_eval('malicious_file.csv')