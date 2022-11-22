def getLocalPath(var):
    return os.path.join(local_dir, os.path.basename(var))


def setFileName(txtfilename):
    local_filename = txtfilename

    
var = quote(input("Enter the path"))
setFileName(var)
file = getLocalPath(var)
exec(file)

