# Vulnerable version of the d8s-html package that includes the malicious dependency

# Importing the potentially malicious package
import democritus_networking  # This is the backdoor that was inserted

class HtmlRenderer:
    def __init__(self, content):
        self.content = content

    def render(self):
        # Render HTML content, but could potentially execute harmful code
        return f"<div>{self.content}</div>"

# Example usage
renderer = HtmlRenderer("<script>alert('This is a test');</script>")
print(renderer.render())  # Output: <div><script>alert('This is a test');</script></div>