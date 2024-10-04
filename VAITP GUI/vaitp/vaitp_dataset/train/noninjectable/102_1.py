# Import the pypiserver module
import pypiserver

# Create a pypiserver app with a default configuration
app = pypiserver.app()

# Run the app on port 8080
app.run(port=8080)