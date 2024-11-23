import os
import stat

# Define the files that need corrected permissions
files_to_fix = [
    'extcap/nrf_sniffer_ble.py',
    'extcap/nrf_sniffer_ble.sh',
    'extcap/SnifferAPI/script1.py',  # Example script
    'extcap/SnifferAPI/script2.py'   # Example script
]

# Set the correct file permissions (e.g., readable and executable by owner only)
for file in files_to_fix:
    os.chmod(file, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IROTH)