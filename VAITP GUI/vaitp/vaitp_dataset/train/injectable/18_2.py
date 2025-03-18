import pickle
import os
import io

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe built-in types.
        safe_builtins = {"list", "dict", "set", "tuple", "str", "int", "float", "bool"}
        if module == "builtins" and name in safe_builtins:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Disallowed class: {module}.{name}")

def safe_loads(s):
    return SafeUnpickler(io.BytesIO(s)).load()

if __name__ == '__main__':
    # For demonstration, use benign data.
    benign_pickle = pickle.dumps({"data": "This is safe."})
    result = safe_loads(benign_pickle)
    print("Secure code executed safely! Result:", result)
