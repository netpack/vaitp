# Import the passeo module
from passeo import passeo

# Generate a password
password = passeo.generate(
    length=12,        # Length of the password
    numbers=True,     # Include numbers
    symbols=True,     # Include symbols
    uppercase=True,   # Include uppercase letters
    lowercase=True,   # Include lowercase letters
    space=False,      # Exclude spaces
    save=False        # Do not save the password
)

# Print the generated password
print(f"Generated Password: {password}")