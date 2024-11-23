# Hard-coded credentials vulnerability example

# This code stores the username and password directly in the source code
USERNAME = "admin"
PASSWORD = "password123"  # Hard-coded password

def authenticate(user, pwd):
    if user == USERNAME and pwd == PASSWORD:
        return True
    return False

def main():
    user_input = input("Enter your username: ")
    pwd_input = input("Enter your password: ")
    
    if authenticate(user_input, pwd_input):
        print("Authentication successful!")
    else:
        print("Authentication failed.")

if __name__ == "__main__":
    main()