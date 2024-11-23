import gnupg

class VulnerableGnuPG:
    def __init__(self, gpg_home):
        self.gpg = gnupg.GPG(gnupghome=gpg_home)

    def import_keys(self, key_data):
        # Vulnerable to option injection through positional arguments
        return self.gpg.import_keys(key_data)

# Example usage
gpg_home = '/path/to/gnupg'
vulnerable_gpg = VulnerableGnuPG(gpg_home)
result = vulnerable_gpg.import_keys('-----BEGIN PGP PUBLIC KEY BLOCK-----\n...')