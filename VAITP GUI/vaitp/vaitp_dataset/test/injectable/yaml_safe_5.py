import yaml
from yaml.loader import SafeLoader

data = open(sys.argv[1], 'r')
yaml.safe_load(data)