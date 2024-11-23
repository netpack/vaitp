from Products.CMFCore.utils import getToolByName
from Products.Five.browser.pagetemplatefile import ViewPageTemplateFile
from plone.api import portal
from plone.dexterity.content import Item
from plone.supermodel import model
from zope import schema
from zope.interface import alsoProvides
from zope.publisher.interfaces.browser import IDefaultBrowserLayer
from zope.schema import TextLine

class IMyContent(model.Schema):
    title = TextLine(title=u"Title", required=True)

class MyContent(Item):
    pass

class MyView:
    template = ViewPageTemplateFile('my_template.pt')

    def __call__(self):
        # Properly escape user input to prevent XSS
        safe_title = self.escape_html(self.context.title)
        return self.template(safe_title=safe_title)

    @staticmethod
    def escape_html(text):
        return ''.join(c if c.isalnum() or c in (' ', '-', '_') else f'&#{ord(c)};' for c in text)