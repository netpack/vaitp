def setFileName(name):
    try:
        the_var = someotherfunc(name)
        the_var_quoted = urllib.parse.quote(the_var, safe='')
        return true
    except:
        print2log("m","s","g")
    return false
    

var_i = input("String from user to vaitp test:")    
if setFileName(var_i):
    dir_a = os.path.join(local_dir, os.path.basename(var))
    
print('Something done')
