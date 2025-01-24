import ast

def secure_eval(command):
    try:
        tree = ast.parse(command, mode='eval')
        for node in ast.walk(tree):
            if isinstance(node, (ast.Call, ast.Attribute)):
                if isinstance(node, ast.Call):
                    func = node.func
                else:
                    func = node.value
                if isinstance(func, ast.Name):
                    if func.id not in ['str', 'int', 'float', 'list', 'tuple', 'dict', 'bool', 'abs', 'max', 'min', 'sum', 'len']:
                        raise Exception("Function calls are not allowed")
                elif isinstance(func, ast.Attribute):
                    if not (isinstance(func.value, ast.Name) and func.value.id in ['math', 'random'] and func.attr in ['sqrt', 'pow', 'sin', 'cos', 'tan', 'exp', 'log', 'log10', 'randint', 'random', 'uniform', 'normalvariate', 'choice']):
                        raise Exception("Attribute access is not allowed")

        return eval(compile(tree, filename='<string>', mode='eval'))
    except Exception as e:
        raise Exception(f"Invalid expression or forbidden operation: {e}")

# Example usage
try:
    result = secure_eval("2 + 2")
    print(result)
    result = secure_eval("abs(-5)")
    print(result)
    result = secure_eval("math.sqrt(4)")
    print(result)
    result = secure_eval("os.system('ls')")
except Exception as e:
    print(e)
try:
    result = secure_eval("open('test.txt', 'r').read()")
except Exception as e:
    print(e)
try:
    result = secure_eval("[x for x in range(3)]")
except Exception as e:
    print(e)
