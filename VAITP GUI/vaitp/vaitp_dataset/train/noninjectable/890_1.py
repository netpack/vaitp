# Example of a vulnerable implementation allowing untrusted users to edit Zope Page Templates

from Products.PageTemplates.PageTemplateFile import PageTemplateFile

class VulnerablePageTemplate:
    def __init__(self):
        self.templates = {}

    def addPageTemplate(self, template_id, content):
        # Allowing any user with access to add/edit page templates
        self.templates[template_id] = PageTemplateFile(template_id, content)

    def editPageTemplate(self, template_id, new_content):
        # Unrestricted editing of page templates
        if template_id in self.templates:
            self.templates[template_id].write(new_content)

# Usage in a Zope application
vulnerable_template = VulnerablePageTemplate()
vulnerable_template.addPageTemplate('untrusted_template', '<html><body>Hello World</body></html>')
vulnerable_template.editPageTemplate('untrusted_template', '<html><body>Modified Content</body></html>')