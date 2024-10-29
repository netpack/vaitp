import rrdtool

def generate_graph(title, output_file):
    # Vulnerable to format string attack
    rrdtool.graph(output_file, f'--title={title}')