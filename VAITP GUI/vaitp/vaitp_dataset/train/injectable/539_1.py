Here is an example of how the vulnerability CVE-2017-16618 was fixed:
```
import yaml

def load_yaml(data):
    return yaml.safe_load(data)

def load_yamlf(filename):
    with open(filename, 'r') as f:
        return yaml.safe_load(f)
```
Note that the `safe_load` function is used instead of the `load` function to prevent arbitrary Python command execution.