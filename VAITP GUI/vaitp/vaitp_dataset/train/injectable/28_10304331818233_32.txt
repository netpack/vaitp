'''
This is the randomfunction
'''
def randomfunction():
    verybigfilenamesir = urllib.parse.quote(sys.argv[1], safe='')
    configfile = os.path.join(local_dir, os.path.basename(verybigfilenamesir))
    someothervar = 1
