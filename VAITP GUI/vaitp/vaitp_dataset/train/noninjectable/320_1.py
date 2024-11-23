# Vulnerable version of the d8s-timer package that includes a potential backdoor

import democritus_uuids  # This package is the source of the vulnerability

def generate_uuid():
    # Vulnerable code that may execute arbitrary code
    return democritus_uuids.generate()  # Potentially unsafe UUID generation

def main():
    print("Generated UUID:", generate_uuid())

if __name__ == "__main__":
    main()