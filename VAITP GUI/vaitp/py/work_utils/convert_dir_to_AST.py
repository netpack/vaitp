import glob, ast, sys, os, subprocess
from os.path import exists

if not sys.argv[1]:
  exit('please input dir as argv1')

class NodeVisitor(ast.NodeVisitor):
    def visit_Str(self, tree_node):
        print("\nTree node:")
        print('{}'.format(tree_node.s))

class NodeTransformer(ast.NodeTransformer):
    def visit_Str(self, tree_node):
        return ast.Str('String: ' + tree_node.s)

for filename in glob.iglob(f'{sys.argv[1]}/*.py'):
    #print()
    #print(f'Processing: {filename}')
    astf = f'ast_temp/{os.path.splitext(filename)[0]}.py'
    f = open(astf,'w')
    fin = open(filename, "r")
    f.write(ast.dump(ast.parse(fin.read(), mode='exec'), indent=4))
    f.close
    fin.close
    if not exists(astf):
      print(f'FAILD TO CREATE AST FILE: {astf}')
    #print()

