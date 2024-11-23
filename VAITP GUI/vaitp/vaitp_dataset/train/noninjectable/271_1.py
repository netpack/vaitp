# Vulnerable code that includes the malicious package
import democritus_hypothesis  # This line introduces the vulnerability

def generate_uuid():
    return democritus_hypothesis.generate()  # Unsafe function call

if __name__ == "__main__":
    print("Generated UUID:", generate_uuid())