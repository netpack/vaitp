import os
import subprocess
from sentry_sdk import init

# Initialize Sentry SDK
init(dsn="your_dsn_here")

# Example of a fixed subprocess call using env={}
subprocess.call(["printenv"], env={})