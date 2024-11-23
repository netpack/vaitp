# Updated requirements list for NVCaffe to exclude the vulnerable gfortran version
required_dependencies = [
    'numpy',
    'scipy',
    'matplotlib',
    # Removed the entry for gfortran version prior to 0.17.4
    # 'gfortran<0.17.4',  # This line has been removed to prevent the vulnerability
]

# Function to install required dependencies safely
def install_dependencies(dependencies):
    import subprocess
    import sys
    
    for package in dependencies:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])

# Install the updated list of dependencies
install_dependencies(required_dependencies)