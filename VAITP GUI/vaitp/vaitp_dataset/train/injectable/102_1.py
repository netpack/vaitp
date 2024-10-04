# Import the pypiserver module
import pypiserver

# Create a pypiserver app with a custom configuration
app = pypiserver.app(
    # Set the root directory for the packages
    root='/path/to/packages',
    # Set the password file for authentication
    password_file='/path/to/htpasswd',
    # Set the fallback URL for non-local packages
    fallback_url='https://pypi.org/simple',
    # Enable HTTPS support
    ssl_context=('/path/to/cert.pem', '/path/to/key.pem')
)

# Run the app on port 8080
app.run(port=8080)