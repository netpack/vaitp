import hashlib, base64, uuid
from cryptography.hazmat.primitives import hashes
from typing import Any, final
class Hashing():
    def __init__(self) -> None:
        self.salt = None
    def __call__(self, *args:Any):
        self.salt = args[0]
    def __str__(self) -> str:
        return "Hashing Funcitions In Here"

    def Standard_Multi_Hash(self,Data:str):
        '''Inreversable Salted Hash Function Don't Use If U Want To Get The Content Back'''
        a = hashlib.sha256(); a.update(bytes(Data.encode())); b = []
        base = hashlib.sha512()
        md = hashlib.md5()
        b.append(str(a.digest()).split("'")[1])
        b[0] = str(base64.urlsafe_b64encode(bytes(b[0].encode()))).split("'")[1]
        base.update(bytes(b[0].encode()))
        md.update(base.digest())
        b[0]=str(base64.urlsafe_b64encode(base64.standard_b64encode(md.digest()))).split("'")[1]
        salt = ['H', 'c', 'D', 'L', 'b', 'M', 'S', 'a', 'N', 'q', 'K', 'j', 'V', 'd', 'O', 'W', 'x']
        c = (b[0].split("G"))or(b[0].split("g"))or(b[0].split("v"))or(b[0].split("x")); d=[]; e=[]
        for i in range(len(c)): a = salt[i]; b = c[i]; c[i] = b+a
        for i in range(len(c)):
            try: d.append(c[i+1])
            except: d.append(c[0])
            e.append(''.join(d))
            final = self.BLAKE2(bytes(str(e[0]).encode()))
            return(final)

    def __Salt(self,data,salt:bytes = None):
        if not salt:
            salts = []
            salts.append(str(hashlib.sha256(uuid.uuid4().bytes).digest()).split("'")[1])
            salts.append(str(data).split("'")[1])
            salts.append(str(hashlib.sha256(uuid.uuid4().bytes).digest()).split("'")[1])
            salts.append(str(hashlib.sha256(uuid.uuid4().bytes).digest()).split("'")[1])
            salts.append(str(data).split("'")[1])
            salts.append(str(data).split("'")[1])
            salts.append(str(hashlib.sha256(uuid.uuid4().bytes).digest()).split("'")[1])
            return base64.standard_b64encode(bytes((str(base64.urlsafe_b64encode(bytes(''.join(salts).encode()))).split("'")[1]+str(base64.urlsafe_b64encode(base64.standard_b64encode((bytes(''.join(salts).encode()))))).split("'")[1]).encode()))
        if salt:
            salts = []
            salts.append(str(hashlib.sha256(salt).digest()).split("'")[1])
            salts.append(str(data).split("'")[1])
            salts.append(str(hashlib.sha256(salt).digest()).split("'")[1])
            salts.append(str(hashlib.sha256(salt).digest()).split("'")[1])
            salts.append(str(data).split("'")[1])
            salts.append(str(data).split("'")[1])
            salts.append(str(hashlib.sha256(salt).digest()).split("'")[1])
            return base64.standard_b64encode(bytes((str(base64.urlsafe_b64encode(bytes(''.join(salts).encode()))).split("'")[1]+str(base64.urlsafe_b64encode(base64.standard_b64encode((bytes(''.join(salts).encode()))))).split("'")[1]).encode()))
        
    def SHA256(self,data:str):
        sha = hashlib.sha256(bytes(data.encode()))
        hash = sha.digest()
        return self.__Salt(hash,salt=self.salt)

    def SHA512(self,data:str):
        sha = hashlib.sha512(bytes(data.encode()))
        hash = str(sha.digest())
        return self.__Salt(hash,salt=self.salt)

    def SHA244(self,data:str):
        sha = hashlib.sha224(bytes(data.encode()))
        hash = str(sha.digest())
        return self.__Salt(hash,salt=self.salt)

    def SHA384(self,data:str):
        sha = hashlib.sha384(bytes(data.encode()))
        hash = str(sha.digest())
        return self.__Salt(hash,salt=self.salt)

    def BLAKE2(self,data:bytes):
        a = hashes.Hash(hashes.BLAKE2s(32))
        a.update(data)
        return self.__Salt(a.finalize(),salt=self.salt)
        