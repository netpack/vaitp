import os
from wheel import bdist_wheel
import shutil
import sys

def create_wheel(package_name):
    # Assuming package_name is provided by user input, which is dangerous
    if not package_name:
        raise ValueError("Package name cannot be empty.")
    
    # Create a temporary directory for the wheel
    temp_dir = f"/tmp/{package_name}"
    os.makedirs(temp_dir, exist_ok=True)

    # Create a setup.py file in the temp directory
    setup_py_content = f"""
from setuptools import setup

setup(
    name='{package_name}',
    version='0.1.0',
    packages=['{package_name}'],
)
"""
    with open(os.path.join(temp_dir, "setup.py"), "w") as f:
      f.write(setup_py_content)

    # Create a package directory with an __init__.py file
    package_dir = os.path.join(temp_dir, package_name)
    os.makedirs(package_dir, exist_ok=True)
    open(os.path.join(package_dir, "__init__.py"), "a").close()


    # Create a wheel distribution
    dist_dir = os.path.join(temp_dir, "dist")
    wheel_cmd = bdist_wheel.bdist_wheel(dist_dir)
    
    #Set the current working directory for bdist_wheel to function correctly
    old_cwd = os.getcwd()
    os.chdir(temp_dir)
    try:
        wheel_cmd.run()
    finally:
        os.chdir(old_cwd)



    # Find the generated wheel file
    wheel_file = None
    for file in os.listdir(dist_dir):
        if file.endswith(".whl"):
            wheel_file = os.path.join(dist_dir, file)
            break
    
    if wheel_file:
        print(f"Wheel created at {wheel_file}")
    else:
        print("Wheel creation failed")

    # Clean up the temp directory
    # shutil.rmtree(temp_dir) # Consider leaving the temp directory for inspection if debugging
    

# Example usage
if __name__ == "__main__":
    user_input = input("Enter the package name: ")
    create_wheel(user_input)