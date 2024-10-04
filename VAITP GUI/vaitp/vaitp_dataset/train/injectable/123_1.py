import tablib
import yaml
# A malicious YAML file that contains Python code
yaml_file = """
- !!python/object/apply:os.system ["echo Hello World"]
"""
# Loading the YAML file as a Databook using a safe loader
databook = tablib.Databook().load("yaml", yaml_file, loader=yaml.SafeLoader)
# The Python code is not executed and raises an exception