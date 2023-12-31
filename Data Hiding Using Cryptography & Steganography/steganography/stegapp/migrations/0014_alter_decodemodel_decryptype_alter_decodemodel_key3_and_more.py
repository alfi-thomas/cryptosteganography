# Generated by Django 4.1.7 on 2023-03-14 09:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stegapp', '0013_alter_decodemodel_decryptype'),
    ]

    operations = [
        migrations.AlterField(
            model_name='decodemodel',
            name='decryptype',
            field=models.CharField(choices=[('Vigenère Cipher', 'Vigenère Cipher'), ('Beaufort Cipher', 'Beaufort Cipher'), ('Autokey Cipher', 'Autokey Cipher'), ('Porta Cipher', 'Porta Cipher')], default='Vigenère Cipher', max_length=50),
        ),
        migrations.AlterField(
            model_name='decodemodel',
            name='key3',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='decodemodel',
            name='key4',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='encodemodel',
            name='encryptype',
            field=models.CharField(choices=[('Vigenère Cipher', 'Vigenère Cipher'), ('Beaufort Cipher', 'Beaufort Cipher'), ('Autokey Cipher', 'Autokey Cipher'), ('Porta Cipher', 'Porta Cipher')], default='Vigenère Cipher', max_length=50),
        ),
        migrations.AlterField(
            model_name='encodemodel',
            name='key1',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='encodemodel',
            name='key2',
            field=models.CharField(max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='encodemodel',
            name='plaintext',
            field=models.CharField(max_length=50, null=True),
        ),
    ]
