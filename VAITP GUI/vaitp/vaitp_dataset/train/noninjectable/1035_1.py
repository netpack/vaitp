import os
import subprocess
from sentry_sdk import init
from sentry_sdk.integrations.stdlib import StdlibIntegration

# Initialize Sentry SDK with Stdlib integration
init(dsn="your_dsn_here", integrations=[StdlibIntegration()])

# Set a sensitive environment variable
os.environ["SECRET_KEY"] = "my_secret_key"

# Subprocess call with env={} expecting no environment variables to be passed
subprocess.call(["printenv"], env={})