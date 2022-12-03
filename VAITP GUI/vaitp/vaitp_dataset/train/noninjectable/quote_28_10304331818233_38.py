def func1(filename):
    check = checksomething(filename)
    if check:
        file = os.path.join(local_dir, os.path.basename(filename))
        os.system(f'ls {file}')
    else:
        print('some error')
       
       
f_name = input
func1(f_name)
