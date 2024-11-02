# Hypothetical due to non open source code
def save_content(data, filename):
    # No permission check
    with open(filename, 'w') as file:
        file.write(data)