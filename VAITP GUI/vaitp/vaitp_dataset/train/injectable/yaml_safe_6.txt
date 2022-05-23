import yaml as yl
from yaml.loader import SafeLoader

data = open(sys.argv[1], 'r')
yl.safe_load(data, Loader=yl.Loader)