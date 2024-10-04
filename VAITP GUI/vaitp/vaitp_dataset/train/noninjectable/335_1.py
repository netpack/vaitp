import os
from git import Repo

# Incorrectly setting a relative path to the 'git' executable
os.environ['GIT_PYTHON_GIT_EXECUTABLE'] = 'git'

# Attempting to use GitPython functions with a relative path
repo = Repo('path/to/your/repo')
print(repo.heads)