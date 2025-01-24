import ast
import traceback
import operator

def safe_eval(expr):
    # Limit the allowed nodes in the AST to prevent unsafe operations
    allowed_nodes = {
        ast.Expression,
        ast.Num,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.Name,
        ast.Load,
        ast.BinOp,
        ast.UnaryOp,
        ast.Compare,
        ast.BoolOp,
        ast.IfExp,
    }
    
    allowed_binops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv,
        ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }

    allowed_unaryops = {
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
        ast.Not: operator.not_,
    }
    
    allowed_cmps = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
        ast.In: operator.contains,
        ast.NotIn: lambda x, y: not operator.contains(y, x),
        
    }

    allowed_boolops = {
      ast.And: lambda x, y: x and y,
      ast.Or: lambda x, y: x or y
    }

    def _safe_eval(node):
      if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
      elif isinstance(node, ast.Num):
          return node.n
      elif isinstance(node, ast.Str):
          return node.s
      elif isinstance(node, ast.List):
          return [_safe_eval(el) for el in node.elts]
      elif isinstance(node, ast.Tuple):
          return tuple(_safe_eval(el) for el in node.elts)
      elif isinstance(node, ast.Dict):
        return { _safe_eval(k): _safe_eval(v) for k, v in zip(node.keys, node.values) }
      elif isinstance(node, ast.Name):
          if node.id == "True":
            return True
          elif node.id == "False":
            return False
          elif node.id == "None":
            return None
          else:
             raise ValueError(f"Name '{node.id}' is not allowed")
      elif isinstance(node, ast.BinOp):
        if type(node.op) not in allowed_binops:
          raise ValueError(f"Binary operator {type(node.op)} not allowed")
        return allowed_binops[type(node.op)](_safe_eval(node.left), _safe_eval(node.right))
      elif isinstance(node, ast.UnaryOp):
          if type(node.op) not in allowed_unaryops:
            raise ValueError(f"Unary operator {type(node.op)} not allowed")
          return allowed_unaryops[type(node.op)](_safe_eval(node.operand))
      elif isinstance(node, ast.Compare):
        left = _safe_eval(node.left)
        for op, right in zip(node.ops, node.comparators):
            if type(op) not in allowed_cmps:
               raise ValueError(f"Comparison operator {type(op)} not allowed")
            
            if not allowed_cmps[type(op)](left,_safe_eval(right)):
                return False
            left = _safe_eval(right)
        return True

      elif isinstance(node, ast.BoolOp):
          if type(node.op) not in allowed_boolops:
            raise ValueError(f"Boolean operator {type(node.op)} not allowed")
          
          values = [_safe_eval(value) for value in node.values]
          
          result = values[0]
          for i in range(1, len(values)):
            result = allowed_boolops[type(node.op)](result,values[i])

          return result
      elif isinstance(node, ast.IfExp):
            test = _safe_eval(node.test)
            if test:
                return _safe_eval(node.body)
            else:
                return _safe_eval(node.orelse)
      else:
        raise ValueError(f"Unsafe node type: {type(node)}")


    # Parse the expression into an AST
    tree = ast.parse(expr, mode='eval')

    # Check for allowed nodes
    _safe_eval(tree)


    # Safely evaluate the expression
    return _safe_eval(tree)


# Example usage
try:
    user_input = "2 + 2"  # This should be controlled input
    result = safe_eval(user_input)
    print("Result:", result)
except Exception as e:
    print("Error:", traceback.format_exc())
