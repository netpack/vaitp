import hashlib
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Crypto:
    def __init__(self, config):
        self._config = config
        self._iv = b'0123456789012345'
        self._allowedKeyEncodings = ['hex', 'utf8', 'base64', 'binary']
        self._allowedKeyLengths = [128, 256]
        self._allowedModes = ['ecb', 'cbc']
        self._defaultOptions = {
            'encryptKey': True,
            'keyEncoding': 'utf8',
            'keyLength': 256,
            'mode': 'cbc',
        }

    def HMACSHA256(self, data):
        key = self._config['secretKey'].encode('utf-8') if isinstance(self._config['secretKey'], str) else self._config['secretKey']
        hashed = hashlib.hmac(key, data.encode('utf-8'), hashlib.sha256)
        return base64.b64encode(hashed.digest()).decode('utf-8')

    def SHA256(self, s):
        hashed = hashlib.sha256(s.encode('utf-8'))
        return hashed.hexdigest()

    def _parseOptions(self, incomingOptions):
        options = incomingOptions or {}
        for key, default_value in self._defaultOptions.items():
            if key not in options:
              options[key] = default_value
        

        if options['keyEncoding'].lower() not in self._allowedKeyEncodings:
            options['keyEncoding'] = self._defaultOptions['keyEncoding']

        if int(options['keyLength']) not in self._allowedKeyLengths:
            options['keyLength'] = self._defaultOptions['keyLength']

        if options['mode'].lower() not in self._allowedModes:
            options['mode'] = self._defaultOptions['mode']

        return options

    def _decodeKey(self, key, options):
        if options['keyEncoding'] == 'base64':
            return base64.b64decode(key)
        if options['keyEncoding'] == 'hex':
            return bytes.fromhex(key)
        return key.encode('utf-8') if isinstance(key, str) else key

    def _getPaddedKey(self, key, options):
        key = self._decodeKey(key, options)
        if options['encryptKey']:
            return bytes.fromhex(self.SHA256(key.decode('utf-8', errors='ignore'))[:32])
        return key

    def _getMode(self, options):
        if options['mode'] == 'ecb':
            return AES.MODE_ECB
        return AES.MODE_CBC

    def _getIV(self, options):
       return self._iv if options['mode'] == 'cbc' else None

    def _getRandomIV(self):
        return get_random_bytes(16)

    def encrypt(self, data, customCipherKey=None, options=None):
       if 'customEncrypt' in self._config and self._config['customEncrypt']:
         return self._config['customEncrypt'](data)
       return self.pnEncrypt(data, customCipherKey, options)

    def decrypt(self, data, customCipherKey=None, options=None):
      if 'customDecrypt' in self._config and self._config['customDecrypt']:
        return self._config['customDecrypt'](data)
      return self.pnDecrypt(data, customCipherKey, options)

    def pnEncrypt(self, data, customCipherKey=None, options=None):
        if not customCipherKey and 'cipherKey' not in self._config:
            return data
        options = self._parseOptions(options)
        mode = self._getMode(options)
        cipherKey = self._getPaddedKey(customCipherKey or self._config.get('cipherKey'), options)
        
        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        
        if self._config.get('useRandomIVs', False):
            iv = self._getRandomIV()
            cipher = AES.new(cipherKey, mode, iv)
            padded_data = pad(data_bytes, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            return base64.b64encode(iv + ciphertext).decode('utf-8')

        iv = self._getIV(options)
        cipher = AES.new(cipherKey, mode, iv)
        padded_data = pad(data_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        return base64.b64encode(ciphertext).decode('utf-8')


    def pnDecrypt(self, data, customCipherKey=None, options=None):
      if not customCipherKey and 'cipherKey' not in self._config:
            return data
      options = self._parseOptions(options)
      mode = self._getMode(options)
      cipherKey = self._getPaddedKey(customCipherKey or self._config.get('cipherKey'), options)
      
      try:
        if self._config.get('useRandomIVs', False):
            decoded_data = base64.b64decode(data)
            iv = decoded_data[:16]
            ciphertext = decoded_data[16:]
            cipher = AES.new(cipherKey, mode, iv)
            
            unpadded_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
            plaintext = unpadded_data.decode('utf-8')
            return json.loads(plaintext)
        else:
            decoded_data = base64.b64decode(data)
            iv = self._getIV(options)
            cipher = AES.new(cipherKey, mode, iv)
            unpadded_data = unpad(cipher.decrypt(decoded_data), AES.block_size)
            plaintext = unpadded_data.decode('utf-8')
            return json.loads(plaintext)
      except Exception:
        return None