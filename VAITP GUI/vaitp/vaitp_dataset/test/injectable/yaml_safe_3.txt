from yaml import safe_load

data = '''
initial hit points: !dice 8d4
'''
safe_load(data)