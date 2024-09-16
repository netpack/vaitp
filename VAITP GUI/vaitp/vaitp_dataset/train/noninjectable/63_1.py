import importlib
import sys

def load_module(module_name):
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.load_module(module)
            return module
        else:
            raise ImportError(f"Module {module_name} not found.")
    except Exception as e:
        print(f"Error loading module {module_name}: {e}")

if __name__ == "__main__":
    module_name = sys.argv[1]
    load_module(module_name)