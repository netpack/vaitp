import os
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64
import yaml


class Vault(object):
    def __init__(self, password):
        self.password = password.encode('utf-8')
        self._key = None

    def _generate_key(self):
      if self._key is None:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.password)
        self._key = digest.finalize()
      return self._key


    def _encrypt(self, data):
        key = self._generate_key()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    def _decrypt(self, data):
        key = self._generate_key()
        try:
            decoded_data = base64.b64decode(data.encode('utf-8'))
            iv = decoded_data[:16]
            ciphertext = decoded_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except Exception:
            raise ValueError("Decryption failed, check password and file")

    def load(self, data):
        if not data:
            return None
        if data.startswith('$ANSIBLE_VAULT;1.1;'):
          try:
            _, _, encrypted = data.split(';', 2)
            decrypted = self._decrypt(encrypted)
            return yaml.safe_load(decrypted)
          except:
            raise ValueError("Vault format error")
        else:
          return yaml.safe_load(data)


    def dump(self, data, file_obj=None):
        if data is None:
          encrypted = None
        else:
          yaml_str = yaml.dump(data)
          encrypted = self._encrypt(yaml_str.encode('utf-8'))
        
        vault_string = '$ANSIBLE_VAULT;1.1;{0}'.format(encrypted) if encrypted else ""

        if file_obj:
            file_obj.write(vault_string)
        else:
            return vault_string