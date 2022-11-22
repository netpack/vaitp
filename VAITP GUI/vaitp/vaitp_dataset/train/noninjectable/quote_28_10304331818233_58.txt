try:
    local_dir = sys.argv[0]
    filename = sys.argv[1]
    name = sys.argv[2]
    lf = os.path.join(local_dir, filename, name)
except:
    print("Please Enter Correct Inputs")
