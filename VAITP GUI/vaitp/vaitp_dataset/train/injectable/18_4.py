import multiprocessing
import pickle
import os
import io
import logging

logging.basicConfig(level=logging.INFO)

# Define a whitelist of safe classes per module.
SAFE_MODULES = {
    "builtins": {"list", "dict", "set", "tuple", "str", "int", "float", "bool"},
    "collections": {"OrderedDict", "defaultdict"}
}

class AdvancedSafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Only allow classes if they are in the whitelist.
        if module in SAFE_MODULES and name in SAFE_MODULES[module]:
            return super().find_class(module, name)
        # Optionally, allow specific safe types from other modules.
        if module == "datetime" and name in {"datetime", "date"}:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Global '{module}.{name}' is forbidden by policy.")

def advanced_safe_loads(s):
    try:
        unpickler = AdvancedSafeUnpickler(io.BytesIO(s))
        result = unpickler.load()
        return result
    except pickle.UnpicklingError as e:
        logging.error("AdvancedSafeUnpickler blocked unsafe pickle data: %s", e)
        return None

def secure_unpickle_complex(data):
    logging.info("Attempting secure unpickle operation.")
    result = advanced_safe_loads(data)
    if result is None:
        logging.info("Data could not be safely unpickled.")
    else:
        logging.info("Data unpickled safely.")
    return result

if __name__ == '__main__':
    benign_data = {"key": "value", "numbers": [1, 2, 3]}
    benign_pickle = pickle.dumps(benign_data)
    with multiprocessing.Pool(processes=1) as pool:
        result = pool.apply(secure_unpickle_complex, (benign_pickle,))
    if result is not None:
        logging.info("Highly complex secure code executed safely with result: %s", result)
    else:
        logging.info("Secure unpickle operation failed safely.")
