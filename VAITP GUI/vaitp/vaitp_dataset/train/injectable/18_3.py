import multiprocessing
import pickle
import io
import logging

logging.basicConfig(level=logging.INFO)

SAFE_BUILTINS = {"list", "dict", "set", "tuple", "str", "int", "float", "bool"}

class ConfigurableSafeUnpickler(pickle.Unpickler):
    def __init__(self, file, safe_modules=None):
        super().__init__(file)
        self.safe_modules = safe_modules or SAFE_BUILTINS

    def find_class(self, module, name):
        if module == "builtins" and name in self.safe_modules:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")

def safe_loads(s, safe_modules=None):
    return ConfigurableSafeUnpickler(io.BytesIO(s), safe_modules=safe_modules).load()

def secure_unpickle(data):
    try:
        return safe_loads(data)
    except pickle.UnpicklingError as e:
        logging.error("Blocked unsafe pickle data: %s", e)
        return None

if __name__ == '__main__':
    benign_pickle = pickle.dumps({"message": "Hello, safe world!"})
    with multiprocessing.Pool(processes=1) as pool:
        result = pool.apply(secure_unpickle, (benign_pickle,))
    if result is not None:
        logging.info("Secure code executed safely with result: %s", result)
