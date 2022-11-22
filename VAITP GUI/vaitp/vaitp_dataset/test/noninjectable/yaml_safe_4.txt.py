from yaml import load

try:
    dir = file('document.yaml', 'w+')
    load(dir, Loader=yaml.Loader)
except:
    print("Unable to Load file")