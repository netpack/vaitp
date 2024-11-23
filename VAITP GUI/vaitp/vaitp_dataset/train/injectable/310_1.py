# Fixed version of the d8s-file-system package without the vulnerable dependency

# Remove the democritus-hashes dependency
# from setup.py or requirements.txt, and ensure it is not imported in the code.

# Example of the fixed setup.py
from setuptools import setup, find_packages

setup(
    name='d8s-file-system',
    version='0.1.1',  # Increment the version to indicate a fix
    packages=find_packages(),
    install_requires=[
        # Do not include 'democritus-hashes' here
    ],
)