# Vulnerable version of the d8s-html package that includes the backdoored democritus-urls package

# Setup.py for the vulnerable package
from setuptools import setup, find_packages

setup(
    name='d8s-html',
    version='0.1.0',  # Affected version
    packages=find_packages(),
    install_requires=[
        'democritus-urls',  # This package contains the backdoor
    ],
)