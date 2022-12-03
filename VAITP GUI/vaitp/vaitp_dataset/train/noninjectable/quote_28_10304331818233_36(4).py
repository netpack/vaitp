def printSomethingFromFS(file_name):
    nome_do_ficheiro = os.path.join(local_dir, os.path.basename(file_name))
    os.system(f'cat {nome_do_ficheiro}')
