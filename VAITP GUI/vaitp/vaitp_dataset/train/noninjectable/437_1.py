from cookiecutter.main import cookiecutter

# Vulnerable code allowing command injection
checkout = "--config=alias.checkout=!touch ./HELLO"
cookiecutter('some valid hg repository', checkout=checkout)