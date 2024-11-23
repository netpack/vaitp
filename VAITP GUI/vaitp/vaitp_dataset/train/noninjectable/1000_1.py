class PollSet:
    def __init__(self):
        self.fd_map = {}

    def poll_set_add_fd(self, fd, event):
        # Vulnerability: Not checking if fd is already in use can lead to use-after-free
        self.fd_map[fd] = event  # Potentially unsafe if fd is freed elsewhere

    def poll_set_remove_fd(self, fd):
        if fd in self.fd_map:
            del self.fd_map[fd]  # Removing fd without proper checks can lead to use-after-free
        else:
            raise ValueError("File descriptor not found.")

# Example usage
poll_set = PollSet()
poll_set.poll_set_add_fd(1, 'READ')
poll_set.poll_set_remove_fd(1)