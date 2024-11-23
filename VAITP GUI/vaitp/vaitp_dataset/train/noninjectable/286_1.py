# Vulnerable version of the package that includes the malicious dependency

# Setup.py with the vulnerable dependency
from setuptools import setup, find_packages

setup(
    name='d8s-asns',
    version='0.1.0',  # Affected version
    packages=find_packages(),
    install_requires=[
        'democritus-csv',  # This dependency introduces the vulnerability
    ],
)