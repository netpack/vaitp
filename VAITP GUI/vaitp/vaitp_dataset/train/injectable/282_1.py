# Fixed version of the d8s-html package that does not include the backdoored democritus-urls package

# Setup.py for the fixed package
from setuptools import setup, find_packages

setup(
    name='d8s-html',
    version='0.1.1',  # Incremented version to indicate a fix
    packages=find_packages(),
    install_requires=[
        # Removed the vulnerable democritus-urls package
        # List only safe dependencies here
    ],
)