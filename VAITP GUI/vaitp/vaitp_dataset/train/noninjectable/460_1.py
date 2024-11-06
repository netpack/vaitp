import json

def load_notebook(file_path):
    with open(file_path, 'r') as f:
        notebook_content = json.load(f)

    # Vulnerable line: executing arbitrary code from the notebook
    exec(notebook_content['cells'][0]['source'])

# Example usage
load_notebook('malicious_notebook.ipynb')

#Example of the content of the ipynb:
# {
#  "cells": [
#   {
#    "cell_type": "code",
#    "metadata": {},
#    "source": [
#     "import os\n",
#     "os.system('echo Malicious code executed!')"
#    ]
#   },
#   {
#    "cell_type": "markdown",
#    "metadata": {},
#    "source": [
#     "<script>alert('This is a malicious script!');</script>"
#    ]
#   }
#  ],
#  "metadata": {
#   "kernelspec": {
#    "display_name": "Python 3",
#    "language": "python",
#    "name": "python3"
#   },
#   "language_info": {
#    "codemirror_mode": {
#     "name": "ipython",
#     "version": 3
#    },
#    "file_extension": ".py",
#    "mimetype": "text/x-python",
#    "name": "python",
#    "nbconvert_exporter": "python",
#    "pygments_lexer": "ipython3",
#    "version": "3.8.5"
#   }
#  },
#  "nbformat": 4,
#  "nbformat_minor": 4
# }