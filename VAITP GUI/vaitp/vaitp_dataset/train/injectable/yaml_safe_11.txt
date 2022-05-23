import yaml as yl

data = open(sys.argv[1], 'r')
yl.safe_load(data, Loader=yl.Loader)