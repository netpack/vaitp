import ast # The vulnerability was fixed by changing the pickle.load() function to ast.literal_eval()

def load_from_file(filename):
    with open(filename, 'rb') as f:
        return ast.literal_eval(f.read())