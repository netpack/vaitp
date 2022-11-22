def funcOnName(f_name, cv):
    if cv:
        exec(os.path.join(local_dir, os.path.basename(f_name)))
    else:
        print(f'Some error regarging cv: {cv}')
f_name = file_name
funcOnName(f_name, othervarnothere)
