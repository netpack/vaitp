from yaml import load

data = '''
initial hit points: !dice 8d4
'''
load(data, Loader=yaml.Loader)