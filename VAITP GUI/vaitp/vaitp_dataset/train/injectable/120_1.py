# This code is for demonstration purposes only. Do not run it on your system.
import webbrowser
import os
import shlex

# Assume that the user input is a URL
user_input = input("Enter a URL: ")

# Get the BROWSER environment variable
browser = os.environ.get("BROWSER")

if browser:
    # Escape any potentially malicious characters in the browser string
    browser = shlex.quote(browser)
    try:
        # Pass the user input and the browser string to the webbrowser module
        webbrowser.get(browser).open(user_input)
    except webbrowser.Error:
        print("Error: Could not open browser with the provided BROWSER environment variable.")
else:
    try:
        webbrowser.open(user_input)
    except webbrowser.Error:
        print("Error: Could not open default browser.")