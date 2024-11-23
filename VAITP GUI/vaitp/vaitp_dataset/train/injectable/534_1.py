import pickle
import os

def safe_load(serialized_data):
    # Use a safer alternative to prevent arbitrary code execution
    # Here we use a custom class to restrict what can be deserialized
    class SafeLoader(pickle.Unpickler):
        def find_class(self, module, name):
            # Restrict loading to only specific classes
            if module == "trusted_module" and name in ["TrustedClass"]:
                return super().find_class(module, name)
            raise pickle.UnpicklingError("Unauthorized access to untrusted class")

    return SafeLoader(io.BytesIO(serialized_data)).load()

# Example usage
try:
    with open("data.pkl", "rb") as f:
        data = safe_load(f.read())
except Exception as e:
    print(f"Error loading data: {e}")