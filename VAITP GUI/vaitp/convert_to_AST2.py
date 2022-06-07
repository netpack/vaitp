
import glob
import ast
import sys
import os

# if not sys.argv[1]:
#   exit('please input dir as argv1')

class NodeVisitor(ast.NodeVisitor):
    def visit_Str(self, tree_node):
        print("\nTree node:")
        print('{}'.format(tree_node.s))


class NodeTransformer(ast.NodeTransformer):
    def visit_Str(self, tree_node):
        return ast.Str('String: ' + tree_node.s)

arr1 = ["train", "test"]
arr2 = ["noninjectable"]

for i in range(2):
    for j in range(1):

        input_folder = str(os.getcwd())+"\\vaitp_dataset\\"+arr1[i]+"\\"+arr2[j]
        output_folder = str(os.getcwd())+"\\vaitp_dataset_ast\\"+arr1[i]+"\\"+arr2[j]
        print(output_folder)
        #file = open("./vaitp_dataset/train/vulnerable/38b.txt", "r")

        """
        tree_node = ast.parse(file.read())


        print("\nAST tree:")
        print(ast.dump(tree_node))



        print("\nAST node visitor:")
        NodeTransformer().visit(tree_node)
        NodeVisitor().visit(tree_node)
        """

        #print("\nAST parser:")
        #print(ast.dump(ast.parse(file.read(), mode='exec'), indent=4))
        c = 0
        for filename in os.listdir(input_folder):
            print(filename)
            print(c)
            if filename.endswith(".txt"):
                astf = os.path.join(output_folder, filename)
                f = open(astf,'w')
                file_path = os.path.join(input_folder, filename)
                fin = open(file_path, "r")
                f.write(ast.dump(ast.parse(fin.read(), mode='exec'), indent=4))
                f.close
                fin.close
                print(f'Created AST file: {astf}')
            c+=1

        # for filename in glob.iglob(f'{sys.argv[1]}/*.txt'):
        #     print(1)
        #     print(filename)
        #     print(f'Processing: {filename}')
        #     astf = f'{os.path.splitext(filename)[0]}.ast'
        #     f = open(astf,'w')
        #     fin = open(filename, "r")
        #     f.write(ast.dump(ast.parse(fin.read(), mode='exec'), indent=4))
        #     f.close
        #     fin.close
        #     print(f'Created AST file: {astf}')

