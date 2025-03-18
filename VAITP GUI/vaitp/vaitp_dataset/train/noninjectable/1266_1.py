import hashlib
import random

class MockCache:
    """
    A simplified, in-memory cache to represent the vulnerable prefix cache in vLLM.
    This is NOT the actual vLLM code, but a demonstration of how hash collisions
    could be exploited to cause cache poisoning.  It focuses on the core hashing issue.
    """
    def __init__(self, cache_size=1024):
        self.cache = {}  # Key: Hash of prefix, Value: Cached result
        self.cache_size = cache_size
        self.use_insecure_hash = True  # Simulate Python 3.12's hash(None) behavior


    def _hash_prefix(self, prefix):
        """Hashes the prefix. Simulates the vulnerable hashing behavior."""
        if self.use_insecure_hash:
          if prefix is None:
              return 12345 # Simulate predictable hash(None) in Python 3.12
          else:
              return hash(prefix)  # Insecure hash function potentially vulnerable to collisions.
        else:
          #More robust hashing (not part of the vulnerable code, but demonstrates a potential fix)
          return hashlib.sha256(prefix.encode('utf-8')).hexdigest()



    def get(self, prefix):
        """Retrieves a result from the cache based on the prefix."""
        key = self._hash_prefix(prefix)
        return self.cache.get(key)


    def put(self, prefix, result):
        """Stores a result in the cache, keyed by the prefix."""
        key = self._hash_prefix(prefix)
        if len(self.cache) < self.cache_size:
            self.cache[key] = result
        else:
            print("Cache is full.  Not adding new entry.")


# Example Usage demonstrating potential collision and cache poisoning.
if __name__ == '__main__':
    cache = MockCache()

    # Simulate an attacker crafting a prefix that collides with None
    # In reality, finding collisions is harder, but this shows the principle.
    attacker_prefix = None  #This demonstrates the core issue related to hash(None)

    #Attacker poisons the cache
    cache.put(attacker_prefix, "ATTACKER_CONTROLLED_RESULT")
    print(f"Attacker injected: {cache.get(attacker_prefix)}")

    # Now, a legitimate user queries using None (simulating a scenario where None
    # is a valid, albeit possibly unintended, input).  They get the attacker's
    # result due to the hash collision!
    legitimate_prefix = None
    result = cache.get(legitimate_prefix)

    print(f"Legitimate user gets (should be correct, but is poisoned): {result}")

    #Demonstrates a non-colliding prefix.  Illustrates that other inputs are not affected.
    safe_prefix = "safe_prefix"
    cache.put(safe_prefix, "SAFE_RESULT")
    print(f"Cache result for '{safe_prefix}': {cache.get(safe_prefix)}")