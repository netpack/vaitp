import csv

def process_csv(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            # Assuming the first column contains the expression
            expression = row[0]
            result = eval(expression)  # Vulnerable use of eval
            print(result)

# Example usage
# process_csv('malicious.csv')