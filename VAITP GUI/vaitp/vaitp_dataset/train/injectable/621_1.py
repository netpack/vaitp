import os
import getpass

def get_credentials():
    # Prompt the user for their username and password instead of using hard-coded values
    username = input("Enter your username: ")
    password = getpass.getpass("Enter your password: ")
    return username, password

def save_credentials(username, password):
    # Save the credentials securely (e.g., using environment variables or a secure vault)
    os.environ['APP_USERNAME'] = username
    os.environ['APP_PASSWORD'] = password

def main():
    username, password = get_credentials()
    save_credentials(username, password)
    print("Credentials saved securely.")

if __name__ == "__main__":
    main()