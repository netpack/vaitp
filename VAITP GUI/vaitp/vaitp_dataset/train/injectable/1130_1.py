from PIL import ImageMath

# Example of a safe usage of ImageMath.eval without allowing arbitrary code execution
# Avoid using the environment parameter to prevent vulnerabilities

# Safe expression evaluation without using environment
result = ImageMath.eval("2 + 2")
print(result)  # Outputs: 4