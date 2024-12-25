import pickle
import io

# Safe unpickling function that only allows specific classes to be unpickled
class SafeUnpickler:
    ALLOWED_CLASSES = (('__main__', 'YourAllowedClass1'), ('__main__', 'YourAllowedClass2')) # Changed to tuples of (module, classname)

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

class YourAllowedClass1:
    def __init__(self, x):
        self.x = x

class YourAllowedClass2:
    def __init__(self, y):
        self.y = y
        
# Example usage (for testing)
obj1 = YourAllowedClass1(10)
pickled_data1 = pickle.dumps(obj1)

obj2 = SafeUnpickler.safe_load(pickled_data1)
print(obj2.x)

obj3 = YourAllowedClass2(20)
pickled_data2 = pickle.dumps(obj3)
obj4 = SafeUnpickler.safe_load(pickled_data2)
print(obj4.y)