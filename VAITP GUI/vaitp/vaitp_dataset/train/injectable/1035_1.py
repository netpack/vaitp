import os
import subprocess
from sentry_sdk import init

# Initialize Sentry SDK
init(dsn="your_dsn_here")

# Example of a vulnerable subprocess call (before the fix)
# This will pass all environment variables to the subprocess
subprocess.call(["printenv"])

# Example of a fixed subprocess call using env={}
subprocess.call(["printenv"], env={})