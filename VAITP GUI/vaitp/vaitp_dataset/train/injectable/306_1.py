# Fixed version of the d8s-pdfs package without the backdoor dependency

# setup.py
from setuptools import setup, find_packages

setup(
    name='d8s-pdfs',
    version='0.1.1',  # Incremented version to indicate a fix
    packages=find_packages(),
    install_requires=[
        # Removed the vulnerable 'democritus-networking' package
        # Add other necessary dependencies here
    ],
)