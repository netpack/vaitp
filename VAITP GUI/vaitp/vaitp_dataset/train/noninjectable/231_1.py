import os
from wheel import bdist_wheel

def create_wheel(package_name):
    # Assuming package_name is provided by user input, which is dangerous
    if not package_name:
        raise ValueError("Package name cannot be empty.")
    
    # Create a temporary directory for the wheel
    temp_dir = f"/tmp/{package_name}"
    os.makedirs(temp_dir, exist_ok=True)

    # Create a wheel distribution
    wheel_cmd = bdist_wheel.bdist_wheel(temp_dir)
    wheel_cmd.run()

    print(f"Wheel created at {temp_dir}/{package_name}.whl")

# Example usage
user_input = input("Enter the package name: ")
create_wheel(user_input)