from yaml import safe_load

try:
    data = '''
    initial hit points: !dice 8d4
    '''
    safe_load(data)
except:
    print("Unable to Load file")