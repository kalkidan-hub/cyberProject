from django.db import models

class Software(models.Model):
    # name = models.CharField(max_length=50)
    signature = models.CharField(max_length=1000)
    public_key = models.IntegerField()