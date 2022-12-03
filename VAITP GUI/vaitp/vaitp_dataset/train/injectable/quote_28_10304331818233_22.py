quotingwithanothervar = urllib.parse.quote(input_raw('input raw query string vaitp'))
py_file = os.path.join(local_dir, os.path.basename(quotingwithanothervar))
exec(f'python {py_file}')
