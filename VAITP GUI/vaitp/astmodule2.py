import ast
from pprint import pprint
import sys
import os
import astunparse

if not sys.argv[1]:
  exit('please input python script as argv1')

def main():
    with open(sys.argv[1], "r") as source:
        code = source.read()
        tree = ast.parse(code, mode='exec')
        print("Full AST tree:")
        print(ast.dump(tree, indent=4))
        print()

    num = 1
    for node in ast.walk(tree):
        #print("NODE:")
        #print(ast.dump(node))


        try:
            param = node.keywords[0].arg
            print(f'{num} node param: {param}') #shell

        except:
            pass

        try:
            #val = node.value.value
            val = node.keywords[0].value.value
            print(f'{num} node val: {val}') #True

        except:
            pass
        

        try:
            #print(f'node args.keywords.value: {val} has parameter: {param}')

            if(
                node.keywords[0].arg == "shell" and node.keywords[0].value.value == False
            ):
                print(f'\nPatch found. Injecting vulnerability...')
                node.keywords[0].value.value = True
                print("Vulnerability injected.")
                print("Recompiling AST to Python...")
                newcode = astunparse.unparse(tree)
                print("\nOld code:")
                print(code)
                print("\nNew code:")
                print(newcode)


        except Exception as e:
            #print(f'Exception: {e}')
            pass

        num+=1

        """

        try:
            '''
            if(
                isinstance(node, ast.Assign)
                and node.targets[0].attr == "value"
                and node.targets[0].value.value.attr == "shell"
            ):
                print("found shell")
            '''
            print(f'node value: {node.value}')

        except:
            pass
       
        


        try:
            print(f'node value.arg: {node.value.arg}')

        except:
            pass
        

        try:
            print(f'node value.value.attr: {node.value.value.attr}')

        except:
            pass
        

        try:
            print(f'node args.arg: {node.args.arg}')

        except:
            pass
        

        try:
            print(f'node args.keywords: {node.keywords}')

        except:
            pass
        
        """


        #if node.
        #   print("keyword found")

        '''
        print("Revelant tree nodes before change:")
        print(tree.body[0].value.keywords[0].arg)
        print(tree.body[0].value.keywords[0].value.value)

        if tree.body[0].value.keywords[0].arg == "shell":
            print("Found posisble injection. Injecting AST...")
            tree.body[0].value.keywords[0].value.value = True
            print("Revelant tree nodes after change:")
            print(tree.body[0].value.keywords[0].arg)
            print(tree.body[0].value.keywords[0].value.value)

        print("Recompiling source code...")
        newcode = astunparse.unparse(tree)
        print(newcode)
        '''

    #analyzer = Analyzer()
    #analyzer.visit(tree)
    #analyzer.report()
    

class NodeVisitor(ast.NodeVisitor):
    def visit_Str(self, tree_node):
        print("\nTree node:")
        print('{}'.format(tree_node.s))


class NodeTransformer(ast.NodeTransformer):
    def visit_Str(self, tree_node):
        return ast.Str('String: ' + tree_node.s)


class Analyzer(ast.NodeVisitor):
    def __init__(self):
        self.stats = {"import": [], "from": []}

    def visit_Import(self, node):
        for alias in node.names:
            self.stats["import"].append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.stats["from"].append(alias.name)
        self.generic_visit(node)

    def report(self):
        pprint(self.stats)


if __name__ == "__main__":
    main()
