# This vulnerability assumes a .toml project like:
    # [ tool.poetry]
    # name = "myproject"
    # version = "1.0.0"

    # [tool.poetry.dependencies]
    # git-repo = { git = "https://github.com/user/repo.git" }

# And a malicious git.exe, as a PoC we can:
    # echo "echo 'Malicious code executed!'" > git.exe
    # chmod +x git.exe
    # mv git.exe /usr/bin/git

#Installing poetry triggers the vulnerability
    # pip install poetry