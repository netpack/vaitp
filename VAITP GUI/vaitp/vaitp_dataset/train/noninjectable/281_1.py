# Vulnerable version of the d8s-domains package including the malicious dependency

# setup.py
from setuptools import setup, find_packages

setup(
    name='d8s-domains',
    version='0.1.0',  # Affected version
    packages=find_packages(),
    install_requires=[
        'democritus-urls',  # This package introduces the backdoor vulnerability
    ],
)