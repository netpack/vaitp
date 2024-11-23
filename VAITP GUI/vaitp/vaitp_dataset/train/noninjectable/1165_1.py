from django.db import models

class Media(models.Model):
    file = models.FileField()

    def save(self, *args, **kwargs):
        # Insufficient input validation
        # This allows any file type to be uploaded without checks
        super().save(*args, **kwargs)