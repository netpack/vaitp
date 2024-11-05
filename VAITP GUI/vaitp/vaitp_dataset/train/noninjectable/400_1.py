# Hypothetical example
# This vulnerability is patched in: https://github.com/plannigan/hyper-bump-it/commit/4454586ccace544924b2f3f48dee62a6083e1226
# Before patch
def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

# Example usage
content = read_file("../../etc/passwd")  # This could allow path traversal
