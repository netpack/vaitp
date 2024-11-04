def diffNotebookCheckpoint(file_name):
    # Vulnerable code that does not sanitize input
    notebook_path = file_name + '.ipynb'
    # Load the notebook and perform diff
    with open(notebook_path, 'r') as f:
        notebook_content = f.read()
    return notebook_content

diffNotebookCheckpoint('malicious<script>alert("XSS")</script>')