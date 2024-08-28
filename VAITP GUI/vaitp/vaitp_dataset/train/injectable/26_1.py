from PIL import ImageMath

# Patched code
expression = "x**2"  # Safe mathematical expression (the vulnerable uses an os command)
ImageMath.eval(expression, x=5)  # Evaluate the expression with a safe context