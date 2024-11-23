# Fixed version of the d8s-pdfs package that does not include the malicious democritus-urls package

# Setup script for the d8s-pdfs package without the backdoor
from setuptools import setup

setup(
    name='d8s-pdfs',
    version='0.1.1',  # Updated version to indicate a fix
    description='A package for handling PDFs securely',
    packages=['d8s_pdfs'],
    install_requires=[
        # Removed 'democritus-urls' to eliminate the backdoor
        # Add other safe dependencies here if needed
    ],
)