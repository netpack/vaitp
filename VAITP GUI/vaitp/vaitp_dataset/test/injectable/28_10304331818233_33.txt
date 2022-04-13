get_file = urllib.parse.quote(thisComesFromSomewhereElse, safe='')
here_we_can_inject_a_payload = os.path.join(local_dir, os.path.basename(get_file))
#This will only run later but the injection may be here
