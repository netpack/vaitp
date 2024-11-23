import pickle

# Safe unpickling function that only allows specific classes to be unpickled
class SafeUnpickler:
    ALLOWED_CLASSES = (YourAllowedClass1, YourAllowedClass2)

    @classmethod
    def safe_load(cls, data):
        # Use a custom Unpickler that restricts the allowed classes
        class RestrictedUnpickler(pickle.Unpickler):
            def find_class(self, module, name):
                # Check if the class is in the allowed list
                if (module, name) not in cls.ALLOWED_CLASSES:
                    raise pickle.UnpicklingError("Class not allowed: {}.{}".format(module, name))
                return super().find_class(module, name)

        return RestrictedUnpickler(io.BytesIO(data)).load()

# Example usage
data = b'...'  # Pickled data
try:
    obj = SafeUnpickler.safe_load(data)
except pickle.UnpicklingError as e:
    print("Unpickling failed:", e)