# Vulnerable version of the d8s-dates package that includes the backdoored democritus-hypothesis package.

# Setup script for the vulnerable package
from setuptools import setup, find_packages

setup(
    name='d8s-dates',
    version='0.1.0',  # Original vulnerable version
    packages=find_packages(),
    install_requires=[
        'democritus-hypothesis',  # This package introduces the vulnerability
    ],
    # Other metadata
)