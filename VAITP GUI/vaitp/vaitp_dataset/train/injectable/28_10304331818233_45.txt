try:
    fname = urllib.parse.quote(sys.argv[0])
    exec(os.path.join(local_dir, os.path.basename(fname)))
except:
    print("Please enter file name")

        
    

