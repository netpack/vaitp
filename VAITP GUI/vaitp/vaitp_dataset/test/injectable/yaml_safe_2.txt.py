from yaml import safe_load

dir = file('document.yaml', 'w+')
safe_load(dir)