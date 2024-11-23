# Vulnerable version of the d8s-file-system package including the backdoored dependency

# Example of the vulnerable setup.py
from setuptools import setup, find_packages

setup(
    name='d8s-file-system',
    version='0.1.0',  # Original version with vulnerability
    packages=find_packages(),
    install_requires=[
        'democritus-hashes',  # Vulnerable dependency that could execute arbitrary code
    ],
)