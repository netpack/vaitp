try:
    f_name = sys.argv[2]
    file = os.path.join(local_dir, os.path.basename(f_name))
except:
    print("Please Enter File Path")