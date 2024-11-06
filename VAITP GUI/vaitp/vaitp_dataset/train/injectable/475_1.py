# autorunwifi.py (after patch)

import os
import subprocess

# This function is called to set up Wi-Fi
def setup_wifi():
    # Use a more secure way to run commands
    try:
        subprocess.run(["iwconfig", "wlan0", "essid", "MyNetwork"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to set up Wi-Fi: {e}")

# Main execution
if __name__ == "__main__":
    setup_wifi()