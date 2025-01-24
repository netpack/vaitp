import os
import tempfile

pth_content = "import site"
code_content = "print('Hello, world!')"

with tempfile.NamedTemporaryFile(mode="w", suffix="._pth", delete=False) as pth_file:
    pth_file.write(pth_content)
pth_filename = pth_file.name

with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as code_file:
    code_file.write(code_content)
code_filename = code_file.name


os.system(f"python -s -E -B -I {code_filename}")


os.remove(pth_filename)
os.remove(code_filename)
