import urllib2

class VulnerableURLField(models.URLField):
    def verify_exists(self, value):
        response = urllib2.urlopen(value)  # No timeout specified
        if response.getcode() != 200:
            raise ValidationError(f'URL does not exist: {value}')