import os

def secure_symlink(target, link_name):
    # Validate the link_name to prevent buffer overflow
    if len(link_name) > 260:  # Windows maximum path length
        raise ValueError("link_name exceeds maximum path length.")

    # Ensure that the target is a valid path
    if not os.path.exists(target):
        raise ValueError("Target does not exist.")

    # Create the symbolic link safely
    os.symlink(target, link_name)

if __name__ == "__main__":
    try:
        secure_symlink("C:\\path\\to\\target", "C:\\path\\to\\link")
        print("Symlink created successfully.")
    except Exception as e:
        print("Error creating symlink:", e)