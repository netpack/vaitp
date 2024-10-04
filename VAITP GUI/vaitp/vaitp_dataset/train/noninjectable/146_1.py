# This code is vulnerable to CVE-2015-5652
# Do not run this code on Windows unless you trust the current working directory
import os
import readline # This will load the readline.pyd file from the current working directory
os.system("whoami") # This will show the current user