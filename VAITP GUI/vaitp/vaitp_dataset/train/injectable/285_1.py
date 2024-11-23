# Fixed version of the code that no longer imports the vulnerable package

# Instead of using the vulnerable democritus-csv package,
# we will use a safe alternative or implement our own CSV handling.

import csv

def safe_csv_read(file_path):
    with open(file_path, mode='r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file)
        for row in reader:
            print(row)

# Example usage
# safe_csv_read('data.csv')