import rrdtool

def vulnerable_graph(filename, title, data):
    # Directly using data without sanitization can lead to format string vulnerabilities
    rrdtool.graph(filename,
                  title=title,
                  data=data)

# Example usage with a potentially dangerous input
vulnerable_graph('output.png', 'Sample Graph', 'Data: %s' % 'Sample data')