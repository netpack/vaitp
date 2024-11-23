import pandas as pd

# Safe usage of pandas to prevent arbitrary file read vulnerability
# Example: Reading a CSV file securely
file_path = 'data.csv'  # Ensure this path is controlled and trusted
df = pd.read_csv(file_path)

# Process the DataFrame as needed
print(df)