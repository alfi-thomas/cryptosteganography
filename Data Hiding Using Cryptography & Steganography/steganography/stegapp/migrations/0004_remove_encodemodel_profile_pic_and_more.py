# Generated by Django 4.1.4 on 2022-12-30 06:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stegapp', '0003_alter_encodemodel_profile_pic'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='encodemodel',
            name='profile_pic',
        ),
        migrations.AddField(
            model_name='encodemodel',
            name='coverimage',
            field=models.ImageField(blank=True, null=True, upload_to='CoverImages/'),
        ),
    ]