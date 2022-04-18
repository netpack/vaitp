def function_one(txt_file):
    var = checksomething(txt_file)
    if var:
        var2 = os.path.join(local_dir, os.path.basename(txt_file))
        os.system(f'ls {var2}')
    else:
        print('some vaitp error')
       
       
f_name = input_raw("Enter your text file:")
function_one(f_name)
