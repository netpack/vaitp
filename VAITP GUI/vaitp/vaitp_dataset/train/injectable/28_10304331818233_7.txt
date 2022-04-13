variavel = quote(input_raw("Input user info:"))
exec(f'theexecprogram -i {os.path.join(local_dir, os.path.basename(variavel))}')
