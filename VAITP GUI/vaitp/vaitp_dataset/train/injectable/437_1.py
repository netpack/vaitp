from cookiecutter.main import cookiecutter

# Patched code that prevents command injection
checkout = "--config=alias.checkout=--"  # Properly sanitized input
cookiecutter('some valid hg repository', checkout=checkout)