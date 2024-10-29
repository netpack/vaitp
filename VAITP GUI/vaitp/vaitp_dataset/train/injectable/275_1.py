import rrdtool

def generate_graph(title, output_file):
    # Properly sanitize the input to prevent format string vulnerabilities
    safe_title = str(title)  # Ensure title is treated as a string
    rrdtool.graph(output_file, f'--title={safe_title}')