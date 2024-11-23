import os
import pwd

def get_pid_info(pid):
    try:
        # Check if the PID exists
        with open(f'/proc/{pid}/status') as f:
            status_info = f.read()
        # Get the user that owns the process
        uid = int(status_info.split('Uid:')[1].split()[0])
        user = pwd.getpwuid(uid).pw_name
        return user, status_info
    except FileNotFoundError:
        return None, None

def secure_read_proc(pid):
    # Ensure the PID belongs to the current user or is a non-privileged process
    user, status_info = get_pid_info(pid)
    if user is None:
        raise ValueError("Invalid PID or process does not exist.")
    
    current_user = pwd.getpwuid(os.getuid()).pw_name
    if user != current_user:
        raise PermissionError("Attempt to read information from a process owned by another user.")

    # Safe to read the process information
    return status_info

# Example usage
try:
    pid = 1234  # Replace with a valid PID
    proc_info = secure_read_proc(pid)
    print(proc_info)
except Exception as e:
    print(f"Error: {e}")