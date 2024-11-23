# Fixed version of the d8s-domains package without the malicious dependency

# setup.py
from setuptools import setup, find_packages

setup(
    name='d8s-domains',
    version='0.1.1',  # Incremented version to indicate a fixed release
    packages=find_packages(),
    install_requires=[
        # Removed the democritus-urls package to eliminate the vulnerability
    ],
)