# Generated by Django 4.1.5 on 2023-01-05 10:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stegapp', '0011_remove_decodemodel_user_remove_encodemodel_user_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='encodemodel',
            name='encryptype',
            field=models.CharField(choices=[('Vigenère Cipher', 'Vigenère Cipher'), ('Beaufort Cipher', 'Beaufort Cipher'), ('Autokey Cipher', 'Autokey Cipher'), ('Porta Cipher', 'Porta Cipher')], default='Vigenère Cipher', max_length=1000),
        ),
    ]