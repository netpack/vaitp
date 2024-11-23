import pandas as pd

def safe_prompt(input_string):
    # This function safely handles user input without executing arbitrary code
    return input_string.strip()

def main():
    user_input = safe_prompt(input("Enter your command: "))
    print(f"User  input is: {user_input}")

if __name__ == "__main__":
    main()