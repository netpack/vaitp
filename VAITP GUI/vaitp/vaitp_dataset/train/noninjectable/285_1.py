# Vulnerable code that imports the democritus-csv package

# This code demonstrates how the vulnerable package was used
# which could potentially allow code execution through the backdoor.

import democritus_csv  # This import introduces the vulnerability

def read_csv(file_path):
    return democritus_csv.load_csv(file_path)

# Example usage
# data = read_csv('data.csv')
# print(data)