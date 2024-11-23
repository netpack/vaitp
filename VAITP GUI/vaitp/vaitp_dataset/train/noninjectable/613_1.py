import yaml
from tastypie.serializers import Serializer

class VulnerableYAMLSerializer(Serializer):
    def from_yaml(self, content):
        # Using yaml.load without a Loader argument is vulnerable
        return yaml.load(content)  # This is unsafe and can execute arbitrary code