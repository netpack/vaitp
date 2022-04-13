sanitized_text = urllib.parse.quote(sys.argv[2])
file = os.path.join(local_dir, os.path.basename(sanitized_text))