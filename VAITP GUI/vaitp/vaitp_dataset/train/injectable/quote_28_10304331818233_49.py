try:
    f_name = os.path.join(local_dir, os.path.basename(urllib.parse.quote(sys.argv[1])))
except:
    print("Please Enter valid File Path")