import gnupg

class SecureGnuPG:
    def __init__(self, gpg_home):
        self.gpg = gnupg.GPG(gnupghome=gpg_home)

    def secure_import_keys(self, key_data):
        # Use keyword arguments to prevent option injection
        return self.gpg.import_keys(key_data, passphrase=None)

# Example usage
gpg_home = '/path/to/gnupg'
secure_gpg = SecureGnuPG(gpg_home)
result = secure_gpg.secure_import_keys('-----BEGIN PGP PUBLIC KEY BLOCK-----\n...')