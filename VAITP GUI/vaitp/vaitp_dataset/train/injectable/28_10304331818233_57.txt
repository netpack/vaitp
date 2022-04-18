def executeInPath():
    str_file = urllib.parse.quote(input_raw("Enter the file:"), safe='')
    final_path = os.path.join(local_dir, os.path.basename(str_file))
    final_cmd = "bash " + final_path
    exec(final_cmd)

    
executeInPath()

