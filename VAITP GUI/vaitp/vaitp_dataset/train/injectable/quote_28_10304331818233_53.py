def random_name():
    name = urllib.parse.quote(input()) # O homem sonha
    file = os.path.join(local_dir, os.path.basename(name)) 

random_name()
