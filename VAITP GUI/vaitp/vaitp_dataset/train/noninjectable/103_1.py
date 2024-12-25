# Import the gnupg module
import gnupg

# Create a GPG object with a default configuration
gpg = gnupg.GPG()

# Generate a symmetric key
# Symmetric keys are not typically generated in this way. Let's just use a passphrase for encryption
# key = gpg.gen_key(gpg.gen_key_input(key_type='RSA', key_length=1024))

# Encrypt some data with a passphrase
data = 'Hello, world!'
encrypted = gpg.encrypt(data, recipients=None, symmetric=True, passphrase='secret\n' + data)

# Print the encrypted data
print(str(encrypted))