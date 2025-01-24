import rrdtool
import shlex

def safe_graph(filename, title, data):
    # Ensure that the data is sanitized to prevent format string vulnerabilities
    # and command injection.
    sanitized_data = shlex.quote(str(data))
    
    # Call the rrdtool.graph function with the sanitized data
    rrdtool.graph(filename,
                  title=title,
                  data=sanitized_data)

# Example usage
safe_graph('output.png', 'Sample Graph', 'Data: Sample data')