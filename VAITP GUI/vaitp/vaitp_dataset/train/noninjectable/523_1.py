from plone.schemaeditor import ManageSchemata
from plone.schemaeditor import SchemaEditor

class VulnerableSchemaEditor(SchemaEditor):
    @ManageSchemata
    def update_schema(self, xml_input):
        # This method can only be called by users with the Manager role
        # Vulnerable XML parsing that allows XXE
        import xml.etree.ElementTree as ET
        return ET.fromstring(xml_input)  # DTD and external entities are processed