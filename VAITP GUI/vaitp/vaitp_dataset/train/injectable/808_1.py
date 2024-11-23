import requests
from django.core.exceptions import ValidationError
from django.db import models

class SafeURLField(models.URLField):
    def verify_exists(self, value):
        try:
            response = requests.head(value, timeout=5)  # Set a timeout to avoid hanging
            if response.status_code != 200:
                raise ValidationError(f'URL does not exist: {value}')
        except requests.exceptions.RequestException as e:
            raise ValidationError(f'Invalid URL: {value} - {str(e)}')