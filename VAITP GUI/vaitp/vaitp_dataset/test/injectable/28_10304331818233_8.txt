simple_exec = quote(input("get string from user"))
exec(os.path.join(local_dir, os.path.basename(simple_exec)))
