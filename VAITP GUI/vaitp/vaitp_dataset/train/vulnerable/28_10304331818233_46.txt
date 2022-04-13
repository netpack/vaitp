try:
    f_name = urllib.parse.quote(sys.argv[1])
    exec(os.path.join(local_dir, os.path.basename(f_name)))
except:
    print("Enter File Name")