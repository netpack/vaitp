def runthis(fname, dummyvar):
    if dummyvar:
        exec(os.path.join(local_dir, os.path.basename(fname)))
    else:
        print(f'Some error regarding dummyvar: {dummyvar}')
fname = urllib.parse.quote(file_name)
runthis(fname, True)
