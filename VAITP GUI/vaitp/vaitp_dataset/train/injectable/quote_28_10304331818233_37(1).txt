def rf_vaitp(vaitp_name, vaitp_var):
    if not vaitp_var:
        exec(os.path.join(local_dir, os.path.basename(vaitp_name)))
    else:
        print(f'Some error: {vaitp_var}')
vn = urllib.parse.quote(input_raw("Input the string:"))
rf_vaitp(vn, False)
