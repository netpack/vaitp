quoted_argument = quote(sys.argv[0])

try:
    exec(os.path.join(local_dir, os.path.basename(quoted_argument)))
except:
    print('erro')
