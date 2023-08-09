from django import forms
# from django.contrib.auth.models import User
from .import models

class encodeform(forms.ModelForm):
    class Meta:
        model = models.encodemodel
        fields = ['plaintext', 'key1', 'key2', 'coverimage', 'encryptype']     

class decodeform(forms.ModelForm):
    class Meta:
        model = models.decodemodel
        fields = ['stegoimage', 'key3', 'key4', 'decryptype']