from setuptools import setup, find_packages

setup(
    name='example_package',
    version='1.0',
    packages=find_packages(),
    install_requires=[
        'numpy',
        'scipy',
        # 'gfortran==0.17.4' gfortran is not a valid python package name
    ]
)