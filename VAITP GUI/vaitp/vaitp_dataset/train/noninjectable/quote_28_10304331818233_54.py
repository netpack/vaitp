check = checksomething(var1, var2)
if check:
    local_filename = os.path.join(local_dir, filename1)
else:
    local_filename = os.path.join(local_dir, filename2)