import subprocess
from astropy.visualization import TransformGraph

# Vulnerable usage of TransformGraph().to_dot_graph
def vulnerable_to_dot_graph(savelayout):
    # Directly using the savelayout argument in subprocess
    graph = TransformGraph()
    dot_graph = graph.to_dot_graph()  # Generate the dot graph

    # This will execute the command provided in savelayout
    subprocess.Popen([savelayout])  # Vulnerable to remote code execution

# Example usage (this could be exploited)
vulnerable_to_dot_graph('malicious_command_or_script')