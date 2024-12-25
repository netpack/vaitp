import os
import sys

# Ensure the script only uses the standard library paths
def secure_import(module_name):
    # Get the standard library paths
    std_lib_paths = [p for p in sys.path if os.path.isdir(p) and p != os.getcwd()]
    
    # Check if the module exists in standard library paths
    for path in std_lib_paths:
        try:
            # Construct the full path to the potential module file
            module_path = os.path.join(path, module_name + ".py")
            if os.path.exists(module_path):
                # If it's a file, use importlib.util.spec_from_file_location to get a spec and then import using importlib.util.module_from_spec
                import importlib.util
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                if spec is not None:
                   module = importlib.util.module_from_spec(spec)
                   spec.loader.exec_module(module)
                   return module
            
            # Check for package (directory)
            package_path = os.path.join(path, module_name)
            init_path = os.path.join(package_path, "__init__.py")
            if os.path.isdir(package_path) and os.path.exists(init_path):
                module = __import__(module_name)
                return module
            
        except ImportError:
            continue
        
    raise ImportError(f"Module {module_name} not found in secure paths.")

# Usage example
if __name__ == "__main__":
    # Example of importing a module securely
    try:
        my_module = secure_import('math') # Changed to 'math' as 'my_module' is not part of the standard library
        print(my_module.sqrt(4))

        #Testing directory package
        import os
        if not os.path.exists("test_package"):
            os.mkdir("test_package")
        with open("test_package/__init__.py", "w") as f:
            f.write("")
        with open("test_package/test_module.py", "w") as f:
            f.write("def hello(): return 'hello'")
        
        sys.path.insert(0, os.getcwd()) # Add current directory to try import
        test_package = secure_import("test_package")
        from test_package import test_module
        print(test_module.hello())
        
        os.remove("test_package/test_module.py")
        os.remove("test_package/__init__.py")
        os.rmdir("test_package")

    except ImportError as e:
        print(e)