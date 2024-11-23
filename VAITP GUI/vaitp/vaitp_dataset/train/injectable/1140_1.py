import csv

def safe_eval(expression):
    # Implement a safe evaluation method or use a library like ast.literal_eval
    raise NotImplementedError("Safe evaluation not implemented.")

def process_csv(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            # Assuming the first column contains the expression
            # Use safe_eval instead of eval
            expression = row[0]
            result = safe_eval(expression)  # Replace eval with safe_eval
            print(result)

# Example usage
# process_csv('malicious.csv')