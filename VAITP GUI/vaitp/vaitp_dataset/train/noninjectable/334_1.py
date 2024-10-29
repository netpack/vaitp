class DBusTestCase:
    def AddTemplate(self, template_name, template_code):
        # Directly executing the provided code without validation
        exec(template_code)

# Example usage
test_case = DBusTestCase()
malicious_code = "__import__('os').system('cat /etc/passwd')"  # Malicious code
test_case.AddTemplate("malicious_template", malicious_code)