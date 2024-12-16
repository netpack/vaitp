import urllib.request
import hashlib
import os

class Version:
    def __init__(self, origin, uri, hash_value, hash_type, filename):
        self.origin = origin
        self.uri = uri
        self.hash_value = hash_value
        self.hash_type = hash_type
        self.filename = filename

    def _download_file(self):
        try:
            urllib.request.urlretrieve(self.uri, self.filename)
        except Exception as e:
            print(f"Error downloading {self.uri}: {e}")
            return False
        return True
    
    def _verify_hash(self):
        if not os.path.exists(self.filename):
            print(f"Error: file {self.filename} does not exist, cannot verify hash.")
            return False
            
        if self.hash_type == 'sha256':
          hasher = hashlib.sha256()
        elif self.hash_type == 'md5':
            hasher = hashlib.md5()
        else:
           print(f"Unsupported hash type: {self.hash_type}")
           return False

        with open(self.filename, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        
        calculated_hash = hasher.hexdigest()

        if calculated_hash == self.hash_value:
            return True
        else:
             print(f"Error: Hash mismatch. Expected {self.hash_value}, got {calculated_hash}")
             return False


    def fetch_binary(self): #Vulnerable
        if not self._download_file():
            return False
        
        # Hashes are not checked here before fix.
        print("Hash verification skipped in vulnerable version. Proceeding despite lack of check")
        return True


    def fetch_source(self): #Vulnerable
      if not self._download_file():
          return False

      # Hashes are not checked here before fix.
      print("Hash verification skipped in vulnerable version. Proceeding despite lack of check")
      return True

class Cache:
    def __init__(self):
       self.archives = []

    def _fetch_archives(self): # Vulnerable
      for archive in self.archives:
            if not archive.fetch_binary():
                print(f"Failed to fetch archive from {archive.uri}")
                return False
      return True

if __name__ == "__main__":
    # Example usage simulating a vulnerable scenario
    
    # Mock a download from unsigned repo.
    
    vulnerable_version_binary = Version(
        origin="http://unsigned-repo.example.com/",
        uri="http://unsigned-repo.example.com/fake-package.deb",
        hash_value="fakehashvalue1234567890abcdef", # Not a real hash
        hash_type="sha256",
        filename="fake-package.deb"
    )

    vulnerable_version_source = Version(
        origin="http://unsigned-repo.example.com/",
        uri="http://unsigned-repo.example.com/fake-package.tar.gz",
        hash_value="fakehashvalue0987654321fedcba", # Not a real hash
        hash_type="md5",
        filename="fake-package.tar.gz"
    )
    
    cache = Cache()
    cache.archives.append(vulnerable_version_binary)
    cache.archives.append(vulnerable_version_source)
    
    print("Starting download using the vulnerable function fetch_binary")
    if cache._fetch_archives():
       print("Download completed successfully in vulnerable scenario.")
    else:
        print("Download failed")
    
    print("Starting download using the vulnerable function fetch_source")
    if vulnerable_version_source.fetch_source():
        print("Download completed successfully in vulnerable scenario.")
    else:
      print("Download failed")

    print("Starting download using the vulnerable function fetch_binary")
    if vulnerable_version_binary.fetch_binary():
      print("Download completed successfully in vulnerable scenario.")
    else:
      print("Download failed")