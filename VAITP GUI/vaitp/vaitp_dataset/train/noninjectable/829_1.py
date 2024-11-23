# Example of a vulnerable Zope Page Template that allows untrusted users to execute TAL expressions

from Products.PageTemplates.PageTemplateFile import PageTemplateFile

class VulnerablePageTemplate(PageTemplateFile):
    def __init__(self, id, text, **kwargs):
        super().__init__(id, text, **kwargs)

    def render(self, *args, **kwargs):
        # This method is vulnerable as it allows execution of arbitrary TAL expressions
        return super().render(*args, **kwargs)

# Usage
# Untrusted users could potentially add/edit this template through the web interface,
# allowing them to execute dangerous TAL expressions indirectly.