# Fixed version of the package that does not include the vulnerable dependency

# Setup.py without the malicious dependency
from setuptools import setup, find_packages

setup(
    name='d8s-asns',
    version='0.1.1',  # Updated version
    packages=find_packages(),
    install_requires=[
        # List only safe dependencies here
        # 'democritus-csv' is removed to eliminate the vulnerability
    ],
)