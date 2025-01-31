
import os
import setuptools
import setuptools.command.test
import sys
import codecs

pkgdir = {"": "python%s" % sys.version_info[0]}
VERSION = "0.18.1"


# `python setup.py test` uses existing Python environment, no virtualenv, no pip.
# Use case: Archlinux package. https://github.com/httplib2/httplib2/issues/103
# Otherwise, use `script/test`
class TestCommand(setuptools.command.test.test):
    user_options = [('test-suite=', None, "Test suite to run")]

    def initialize_options(self):
        setuptools.command.test.test.initialize_options(self)
        self.test_suite = None

    def finalize_options(self):
        setuptools.command.test.test.finalize_options(self)
        self.test_args = []
        if self.test_suite is not None:
            self.test_args.append('-k')
            self.test_args.append(self.test_suite)

    def run_tests(self):
        # pytest may be not installed yet
        import pytest

        errno = pytest.main(self.test_args)
        sys.exit(errno)


def read_requirements(name):
    project_root = os.path.dirname(os.path.abspath(__file__))
    with codecs.open(os.path.join(project_root, name), "r", encoding='utf-8') as f:
        # remove whitespace and comments
        g = (line.strip().split("#", 1)[0].rstrip() for line in f)
        return [l for l in g if l]


setuptools.setup(
    name="httplib2",
    version=VERSION,
    author="Joe Gregorio",
    author_email="joe@bitworking.org",
    url="https://github.com/httplib2/httplib2",
    description="A comprehensive HTTP client library.",
    license="MIT",
    long_description="""

A comprehensive HTTP client library, ``httplib2`` supports many features left out of other HTTP libraries.

**HTTP and HTTPS**
  HTTPS support is only available if the socket module was compiled with SSL support.


**Keep-Alive**
  Supports HTTP 1.1 Keep-Alive, keeping the socket open and performing multiple requests over the same connection if possible.


**Authentication**
  The following three types of HTTP Authentication are supported. These can be used over both HTTP and HTTPS.

  * Digest
  * Basic
  * WSSE

**Caching**
  The module can optionally operate with a private cache that understands the Cache-Control:
  header and uses both the ETag and Last-Modified cache validators. Both file system
  and memcached based caches are supported.


**All Methods**
  The module can handle any HTTP request method, not just GET and POST.


**Redirects**
  Automatically follows 3XX redirects on GETs.


**Compression**
  Handles both 'deflate' and 'gzip' types of compression.


**Lost update support**
  Automatically adds back ETags into PUT requests to resources we have already cached. This implements Section 3.2 of Detecting the Lost Update Problem Using Unreserved Checkout


**Unit Tested**
  A large and growing set of unit tests.
""",
    package_dir=pkgdir,
    packages=["httplib2"],
    package_data={"httplib2": ["*.txt"]},
    install_requires=read_requirements("requirements.txt"),
    tests_require=read_requirements("requirements-test.txt"),
    cmdclass={"test": TestCommand},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries",
    ],
)