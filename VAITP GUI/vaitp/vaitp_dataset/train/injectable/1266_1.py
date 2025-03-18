import hashlib

def fixed_hash(input_str):
    """
    A more secure hashing function to mitigate hash collision vulnerabilities.
    Uses SHA-256 for stronger collision resistance and includes a salt.
    """
    salt = "your_secret_salt"  # Replace with a strong, randomly generated secret
    combined_str = salt + str(input_str)  # Ensure input is a string
    hashed_str = hashlib.sha256(combined_str.encode('utf-8')).hexdigest()
    return hashed_str


def prefix_caching(prompt, cache):
    """
    Demonstrates prefix caching with a fix for potential hash collisions.

    Args:
        prompt: The input prompt string.
        cache: A dictionary representing the cache.  Keys are hash values,
               values are the cached results.
    """
    hash_value = fixed_hash(prompt)

    if hash_value in cache:
        print(f"Cache hit for prompt: {prompt}")
        return cache[hash_value]
    else:
        print(f"Cache miss for prompt: {prompt}")
        result = f"Result for: {prompt}"  # Simulate a computation
        cache[hash_value] = result
        return result


if __name__ == '__main__':
    cache = {}

    # Example usage with potentially colliding prompts using the vulnerable hash
    prompt1 = "The quick brown fox"
    prompt2 = "The slow black dog"  # Simulate another prompt

    result1 = prefix_caching(prompt1, cache)
    print(f"Result 1: {result1}")

    result2 = prefix_caching(prompt2, cache)
    print(f"Result 2: {result2}")