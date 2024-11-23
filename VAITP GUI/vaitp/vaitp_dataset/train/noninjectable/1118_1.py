import os

# Example of setting incorrect file permissions
files_to_insecure = [
    'extcap/nrf_sniffer_ble.py',
    'extcap/nrf_sniffer_ble.sh',
    'extcap/SnifferAPI/script1.py',  # Example script
    'extcap/SnifferAPI/script2.py'   # Example script
]

# Set insecure file permissions (e.g., writable and executable by everyone)
for file in files_to_insecure:
    os.chmod(file, 0o777)  # Read, write, and execute permissions for all