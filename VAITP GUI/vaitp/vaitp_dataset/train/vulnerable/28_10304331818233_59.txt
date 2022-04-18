try:
    local_dir = sys.argv[0]
    filename = sys.argv[1]
    lf = os.path.join(local_dir, filename, "file_name.txt")
except:
    print("Please Enter Correct Inputs")
