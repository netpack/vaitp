from RestrictedPython import compile_restricted, safe_builtins, limited_builtins

def execute_restricted(code, global_vars=None, local_vars=None):
    if global_vars is None:
        global_vars = {}
    if local_vars is None:
        local_vars = {}
    byte_code = compile_restricted(code, filename="<string>", mode="exec")
    exec(byte_code, global_vars, local_vars)
    
    
# Vulnerable code example - simulates the type confusion with try/except*
code = """
class Evil:
  def __init__(self, x):
    self.x = x
  def __enter__(self):
    return self
  def __exit__(self, exc_type, exc_val, exc_tb):
    global exploit
    exploit = 1
    return True
try:
    raise ExceptionGroup("msg", [1])
except* Exception as e:
    
    with Evil(1):
      pass
    
"""
exploit = 0
execute_restricted(code, global_vars = {"exploit":exploit}, local_vars = {})

print(f"Exploit triggered: {exploit}")