def runthis(fname, dummyvar):
    if dummyvar:
        exec(os.path.join(local_dir, os.path.basename(fname)))
    else:
        print(f'Some error regarging dummyvar: {dummyvar}')
fname = file_name
runthis(fname, True)
