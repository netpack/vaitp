import os

def get_pid_info(pid):
    # This function reads process information from /proc/pid
    try:
        with open(f'/proc/{pid}/status') as f:
            return f.read()
    except FileNotFoundError:
        return None

def read_process_info(pid):
    # Unrestricted reading of process information
    proc_info = get_pid_info(pid)
    if proc_info:
        print(f"Process {pid} info:\n{proc_info}")
    else:
        print(f"No information found for PID {pid}")

# Example usage
pid = 1234  # Replace with a valid PID
read_process_info(pid)