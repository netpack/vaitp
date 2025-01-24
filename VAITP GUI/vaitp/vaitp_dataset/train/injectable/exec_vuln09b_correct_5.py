import ast
import inspect

def some_random_name(inp):
    try:
        parsed_input = ast.parse(inp)
        
        for node in ast.walk(parsed_input):
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call, ast.Attribute, ast.Subscript)):
                  if isinstance(node, ast.Call):
                     if isinstance(node.func, (ast.Name,ast.Attribute)):
                         if isinstance(node.func,ast.Name):
                             if node.func.id not in ['int','float','str','list','dict','tuple','set','bool','len','abs','min','max','sum','round','sorted','any','all','ord','chr']:
                                 raise ValueError("Unsupported operation: function call.")
                         elif isinstance(node.func, ast.Attribute):
                            if isinstance(node.func.value, ast.Name):
                              if node.func.value.id not in ['math','random']:
                                  raise ValueError("Unsupported operation: attribute access.")
                            else:
                                raise ValueError("Unsupported operation: attribute access.")
                     else:
                         raise ValueError("Unsupported operation: function call.")
                  elif isinstance(node, (ast.Attribute, ast.Subscript)):
                     raise ValueError("Unsupported operation: attribute or subscript.")
                  else:
                     raise ValueError("Unsupported operation: import statement.")

        
        compiled_code = compile(parsed_input, filename="<string>", mode="exec")
        
        local_namespace = {}
        exec(compiled_code, {}, local_namespace)
        if "output" in local_namespace:
            return local_namespace["output"]
        else:
          return None
    except (SyntaxError, TypeError, ValueError) as e:
        return None