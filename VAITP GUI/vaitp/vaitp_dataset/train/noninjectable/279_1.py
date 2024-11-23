# Vulnerable version of the package with the malicious dependency

from setuptools import setup, find_packages

setup(
    name='d8s-mpeg',
    version='0.1.0',  # Affected version
    packages=find_packages(),
    install_requires=[
        'democritus-networking',  # This dependency introduces the backdoor
    ],
)