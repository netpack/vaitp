def random_execution(inf):
    exec(os.path.join(local_dir, os.path.basename(inf)))
    


random_execution(file_name)
