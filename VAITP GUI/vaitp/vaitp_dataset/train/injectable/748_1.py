import rrdtool

def safe_graph(filename, title, data):
    # Ensure that the data is sanitized to prevent format string vulnerabilities
    sanitized_data = str(data).replace('%', '%%')
    
    # Call the rrdtool.graph function with the sanitized data
    rrdtool.graph(filename,
                  title=title,
                  data=sanitized_data)

# Example usage
safe_graph('output.png', 'Sample Graph', 'Data: %s' % 'Sample data')