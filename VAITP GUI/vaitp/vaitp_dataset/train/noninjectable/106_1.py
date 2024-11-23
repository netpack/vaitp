import os

def vulnerable_symlink(target, link_name):
    # No validation on link_name, which can lead to a buffer overflow
    os.symlink(target, link_name)

if __name__ == "__main__":
    # Example of an attacker-controlled link_name that could exploit the vulnerability
    attacker_controlled_target = "C:\\path\\to\\target"
    attacker_controlled_link_name = "C:\\path\\to\\very_long_link_name_that_exceeds_the_buffer_limit"

    try:
        vulnerable_symlink(attacker_controlled_target, attacker_controlled_link_name)
        print("Symlink created successfully.")
    except Exception as e:
        print("Error creating symlink:", e)