import os
import git  # This is GitPython

# Specify the path to the legitimate git executable
# Ensure to adjust this path according to your Git installation
git_executable_path = r'C:\Program Files\Git\cmd\git.exe'

# Now we will run a Git command using GitPython with the specified executable
try:
    # Set the GIT_PYTHON_GIT_EXECUTABLE environment variable
    os.environ['GIT_PYTHON_GIT_EXECUTABLE'] = git_executable_path
    
    repo = git.Repo('.')
    print(repo.git.status())  # This will invoke the legitimate git.exe
except Exception as e:
    print(f"Error: {e}")