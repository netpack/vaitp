import pickle
import io

# Define a safe unpickler class that restricts what can be unpickled
class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        # Restrict unpickling to only safe classes
        if module == "safe_module" and name in ["SafeClass1", "SafeClass2"]:
            return super().find_class(module, name)
        raise pickle.UnpicklingError("Unauthorized unpickling attempt!")

def safe_load_pickle(data):
    return SafeUnpickler(io.BytesIO(data)).load()

# Usage example
if __name__ == "__main__":
    # Example of loading a pickle file safely
    try:
        with open("safe_data.pkl", "rb") as f:
            data = f.read()
            obj = safe_load_pickle(data)
            print("Successfully loaded safe object:", obj)
    except FileNotFoundError as e:
        print("Failed to find file:", e)
    except pickle.UnpicklingError as e:
        print("Failed to unpickle data:", e)