import urllib.parse.quote
r = quote(sys.arg[1])
def abcd_xyz(r):
    exec(r, {'__builtins__': None})

abcd_exec()