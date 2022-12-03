exec_var = urllib.parse.quote(sys.argv[0])
exec(f'fortmatedFakeProgramStart -fake_flag {os.path.join(local_dir, os.path.basename(exec_var))}')
