import glob, ast, sys, os, subprocess
from os.path import exists

listoffilestoignore = [
   "979_1", "1004_1", "1008_1", "1009_1", "1216_1" #vyper
]

if not sys.argv[1]:
  exit('please input dir as argv1')

class NodeVisitor(ast.NodeVisitor):
    def visit_Str(self, tree_node):
        print("\nTree node:")
        print('{}'.format(tree_node.s))

class NodeTransformer(ast.NodeTransformer):
    def visit_Str(self, tree_node):
        return ast.Constant('String: ' + tree_node.s)

for filename in glob.iglob(f'{sys.argv[1]}/*.py'):
    #print()
    filenamewithoutext = os.path.splitext(os.path.basename(filename))[0]
    print(f'Processing: {filenamewithoutext}')

    if not filenamewithoutext in listoffilestoignore:

      astf = f'{sys.argv[1]}/ast_temp/{filenamewithoutext}.txt'
      f = open(astf,'w')
      fin = open(filename, "r")
      f.write(ast.dump(ast.parse(fin.read(), mode='exec'), indent=4))
      f.close
      fin.close
      if not exists(astf):
        print(f'FAILD TO CREATE AST FILE: {astf}')
      #print()

