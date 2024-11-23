def vulnerable_prompt():
    # This function is vulnerable as it executes arbitrary code from user input
    user_input = input("Enter your command: ")
    exec(user_input)

def main():
    vulnerable_prompt()

if __name__ == "__main__":
    main()