import os
import uuid
from django.db import models

def get_cover_image_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f'{uuid.uuid4().hex}.{ext}'
    return os.path.join('coverimage', 'CoverImage', filename)

def get_stego_image_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f'{uuid.uuid4().hex}.{ext}'
    return os.path.join('stegoimage', 'StegoImage', filename)

class encodemodel(models.Model):
    plaintext = models.CharField(max_length=500, null=True)
    key1 = models.CharField(max_length=20, null=True)
    key2 = models.CharField(max_length=20, null=True)
    encryptype = models.CharField(max_length=500, choices=[('Vigenère Cipher', 'Vigenère Cipher'),('Beaufort Cipher','Beaufort Cipher'),('Autokey Cipher','Autokey Cipher'),('Porta Cipher','Porta Cipher')], default="Vigenère Cipher")
    coverimage = models.ImageField(upload_to=get_cover_image_path, null=True, blank=True)

class decodemodel(models.Model):
    stegoimage = models.ImageField(upload_to=get_stego_image_path, null=True, blank=True)
    key3 = models.CharField(max_length=20, null=True)
    key4 = models.CharField(max_length=20, null=True)
    decryptype = models.CharField(max_length=500, choices=[('Vigenère Cipher', 'Vigenère Cipher'),('Beaufort Cipher','Beaufort Cipher'),('Autokey Cipher','Autokey Cipher'),('Porta Cipher','Porta Cipher')], default="Vigenère Cipher")