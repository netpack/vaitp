# Fixed version of the package without the backdoor

# Setup the package without the malicious dependency
from setuptools import setup, find_packages

setup(
    name='d8s-mpeg',
    version='0.1.1',  # Updated version to indicate the fix
    packages=find_packages(),
    install_requires=[
        # Removed 'democritus-networking' to eliminate the backdoor
    ],
)