import os
import re
from wheel import bdist_wheel

def is_valid_package_name(package_name):
    # Validate package name: must be alphanumeric and can include dashes and underscores
    return bool(re.match(r'^[a-zA-Z0-9-_]+$', package_name))

def create_wheel(package_name):
    # Validate the package name before proceeding
    if not is_valid_package_name(package_name):
        raise ValueError("Invalid package name. Only alphanumeric characters, dashes, and underscores are allowed.")

    # Create a temporary directory for the wheel
    temp_dir = f"/tmp/{package_name}"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        # Create a wheel distribution
        wheel_cmd = bdist_wheel.bdist_wheel(temp_dir)
        wheel_cmd.run()
        print(f"Wheel created at {temp_dir}/{package_name}.whl")
    except Exception as e:
        print(f"An error occurred while creating the wheel: {e}")
    finally:
        # Clean up the temporary directory if needed
        if os.path.exists(temp_dir):
            os.rmdir(temp_dir)

# Example usage
user_input = input("Enter the package name: ")
create_wheel(user_input)