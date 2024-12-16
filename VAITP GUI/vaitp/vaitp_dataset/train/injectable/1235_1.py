import logging
import re

# ... other zhmcclient code ...

def log_partition_update(partition_data):
    # ... existing code ...

    #Vulnerable code (before fix)
    #logging.getLogger("zhmcclient.api").info(f"Partition update: {partition_data}")
    #logging.getLogger("zhmcclient.hmc").info(f"Partition update: {partition_data}")

    #Fix: Mask sensitive data before logging
    masked_data = mask_sensitive_data(partition_data)
    logging.getLogger("zhmcclient.api").info(f"Partition update: {masked_data}")
    logging.getLogger("zhmcclient.hmc").info(f"Partition update: {masked_data}")



def mask_sensitive_data(data):
    masked_data = data.copy() #avoid modifying original data
    for key in ["boot-ftp-password", "ssc-master-pw", "zaware-master-pw", "password", "bind-password"]:
        if key in masked_data:
            masked_data[key] = "***MASKED***"
    return masked_data

# Example Usage (Illustrative):
partition_data = {
    "name": "mypartition",
    "boot-ftp-password": "mysecretpassword",
    "other_property": "somevalue"
}

log_partition_update(partition_data)
