# Example fix for CVE-2023-7152 in MicroPython's poll_set_add_fd function

class PollSet:
    def __init__(self):
        self.fd_map = {}

    def poll_set_add_fd(self, fd, event):
        if fd in self.fd_map:
            # Prevent use-after-free by ensuring the fd is valid before adding
            raise ValueError("File descriptor already in use.")
        
        # Simulate adding a file descriptor to the poll set
        self.fd_map[fd] = event

    def poll_set_remove_fd(self, fd):
        if fd in self.fd_map:
            # Safely remove the file descriptor
            del self.fd_map[fd]
        else:
            raise ValueError("File descriptor not found.")

# Example usage
poll_set = PollSet()
poll_set.poll_set_add_fd(1, 'READ')
poll_set.poll_set_remove_fd(1)