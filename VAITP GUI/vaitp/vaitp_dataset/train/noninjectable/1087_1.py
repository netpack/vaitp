import pandas as pd

# Example of potentially unsafe code that could lead to arbitrary file read
file_path = input("Enter the path of the file to read: ")
df = pd.read_csv(file_path)

# Process the DataFrame as needed
print(df)