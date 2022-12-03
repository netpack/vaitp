from yaml import load

dir = file('document.yaml', 'w+')
load(dir, Loader=yaml.Loader)