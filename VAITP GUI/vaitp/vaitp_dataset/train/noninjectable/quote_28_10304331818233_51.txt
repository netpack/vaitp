def func1(filename):
    check = checksomething(filename)
    if check:
        file = os.path.join(local_dir, os.path.basename(filename))
        os.system(f'ls {file}')
    else:
        print('some error 2')
       
try:       
    f_name = sys.argv[1]
    func1(f_name)
except:
    print("Some Error 1")