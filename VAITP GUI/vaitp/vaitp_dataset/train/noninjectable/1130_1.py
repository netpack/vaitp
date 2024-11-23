from PIL import ImageMath

# Example of using ImageMath.eval with the environment parameter, which is vulnerable
# This allows arbitrary code execution

# Unsafe expression evaluation using environment
env = {"__builtins__": None}  # Restrict built-ins for safety
result = ImageMath.eval("os.system('echo Vulnerable!')", env=env)
print(result)