argv1 = urllib.parse.quote(sys.argv[1], safe='')
#some comment
a = 1
#some other non-related content
callThisFuncion(a)
if a == 1:
    exec(os.path.join(local_dir, os.path.basename(argv1)))
    #some other comment
    a = a+2 #Some other computation
