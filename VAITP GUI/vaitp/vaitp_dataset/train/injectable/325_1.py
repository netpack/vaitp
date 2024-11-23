# Fixed version of the d8s-dates package after CVE-2022-44052
# Ensure that the package does not import any untrusted third-party code.

# Safe import statement
import datetime

# Example function that uses safe datetime functionalities
def get_current_time():
    return datetime.datetime.now()

# Example usage
if __name__ == "__main__":
    print("Current time:", get_current_time())