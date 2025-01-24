import csv
import ast

def safe_eval(expression):
    try:
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        return None

def process_csv(file_path):
    with open(file_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if row:
                expression = row[0]
                result = safe_eval(expression)
                if result is not None:
                    print(result)

# Example usage
# process_csv('malicious.csv')
