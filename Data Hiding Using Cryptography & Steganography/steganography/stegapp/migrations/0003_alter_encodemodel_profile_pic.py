# Generated by Django 4.1.4 on 2022-12-28 08:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('stegapp', '0002_remove_encodemodel_img_encodemodel_profile_pic'),
    ]

    operations = [
        migrations.AlterField(
            model_name='encodemodel',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='profile_pic/CustomerProfilePic/'),
        ),
    ]
