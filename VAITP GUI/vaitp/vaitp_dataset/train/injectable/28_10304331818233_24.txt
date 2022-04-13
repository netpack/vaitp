var3 = urllib.parse.quote(sys.argv[1])
out = os.path.join(local_dir, os.path.basename(var3))
if someothervar==1:
    exec(out)
elif someothervar==2:
    print(f'The value of someothervar is 2 and exec had {out}')
else:
    raise customError #more entropy
'''
this is another multi-line vaito comment
just some more text here
'''
