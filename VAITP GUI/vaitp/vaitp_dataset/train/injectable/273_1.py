# Fixed version of the d8s-dates package that does not include the backdoored democritus-hypothesis package.

# Setup script for the fixed package
from setuptools import setup, find_packages

setup(
    name='d8s-dates',
    version='0.1.1',  # Updated version to indicate fix
    packages=find_packages(),
    install_requires=[
        # Removed the potentially malicious package
        # 'democritus-hypothesis',  # This line has been removed
    ],
    # Other metadata
)