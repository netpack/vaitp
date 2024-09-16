import importlib
import sys

def load_module(module_name):
    # Check if the module is in a trusted directory
    trusted_dirs = ["/usr/lib/python3.8/site-packages", "/usr/local/lib/python3.8/site-packages"]
    for dir in trusted_dirs:
        try:
            spec = importlib.util.find_spec(module_name, package_name=dir)
            if spec is not None:
                module = importlib.util.module_from_spec(spec)
                spec.loader.load_module(module)
                return module
        except Exception as e:
            pass

    # Check if the module is in a whitelist of allowed modules
    whitelist = ["pandas", "math"] # examples
    if module_name in whitelist:
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            module = importlib.util.module_from_spec(spec)
            spec.loader.load_module(module)
            return module

    raise ImportError(f"Module {module_name} not found or allowed.")

if __name__ == "__main__":
    module_name = sys.argv[1]
    load_module(module_name)