# Example of a fixed version of the d8s-html package that does not include the backdoor

# Fixed version of the package without the malicious dependency
# This version does not import or use the democritus-networking package

class SafeHtmlRenderer:
    def __init__(self, content):
        self.content = content

    def render(self):
        # Safely render HTML content without executing any potentially harmful code
        return f"<div>{self.escape_html(self.content)}</div>"

    @staticmethod
    def escape_html(text):
        # Escape HTML to prevent injection attacks
        escape_table = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#x27;",
        }
        return ''.join(escape_table.get(c, c) for c in text)

# Example usage
renderer = SafeHtmlRenderer("<script>alert('This is a test');</script>")
print(renderer.render())  # Output: <div>&lt;script&gt;alert('This is a test');&lt;/script&gt;</div>