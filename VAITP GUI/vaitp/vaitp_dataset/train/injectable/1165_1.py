from django.core.exceptions import ValidationError
from django.utils.deconstruct import deconstructible
import os

@deconstructible
class FileExtensionValidator:
    def __init__(self, allowed_extensions):
        self.allowed_extensions = allowed_extensions

    def __call__(self, value):
        ext = os.path.splitext(value.name)[1]
        if ext.lower() not in self.allowed_extensions:
            raise ValidationError(f'File extension not allowed: {ext}')

# Usage in a Django model
from django.db import models

class Media(models.Model):
    file = models.FileField(validators=[FileExtensionValidator(['.mp4', '.avi', '.mov'])])