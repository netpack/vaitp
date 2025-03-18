import multiprocessing
import pickle
import os
import io

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow safe built-in types.
        safe_builtins = {
            'list', 'dict', 'set', 'tuple', 'str', 'int', 'float', 'bool', 'complex'
        }
        if module == "builtins" and name in safe_builtins:
            return super().find_class(module, name)
        # Block everything else (like os.system or any custom malicious classes)
        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden for security reasons.")

def safe_loads(s):
    return SafeUnpickler(io.BytesIO(s)).load()

# A malicious object (for testing purposes)
class Malicious(object):
    def __reduce__(self):
        # This would normally trigger arbitrary code execution
        return (os.system, ('head -n 30 /etc/passwd',))

if __name__ == "__main__":
    # Create a pickle that would normally be dangerous
    malicious_pickle = pickle.dumps(Malicious())

    try:
        with multiprocessing.Pool(processes=1) as pool:
            # Instead of using pickle.loads (which is unsafe), we use safe_loads.
            # This should raise an UnpicklingError rather than executing the payload.
            pool.apply(safe_loads, (malicious_pickle,))
    except pickle.UnpicklingError as e:
        print("Blocked unsafe pickle data:", e)

    print("Secure code executed without triggering the vulnerability.")
