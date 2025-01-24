from os import file

dir = file('document.yaml', 'r')

yaml.safe_load(dir)