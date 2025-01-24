import biplist
import plistlib

filename = "malicious.plist"

try:
    with open(filename, "rb") as file:
        try:
            plist = plistlib.load(file)
            print(plist)
        except (plistlib.InvalidFileException, Exception) as e:
             print(f"Error parsing plist using plistlib: {e}")
except FileNotFoundError:
    print(f"Error: File not found: {filename}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")