import yaml
from tastypie.serializers import Serializer

class SafeYAMLSerializer(Serializer):
    def from_yaml(self, content):
        # Use safe_load to prevent execution of arbitrary code
        return yaml.safe_load(content)