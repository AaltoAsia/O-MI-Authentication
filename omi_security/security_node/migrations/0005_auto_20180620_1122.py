# Generated by Django 2.0.4 on 2018-06-20 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('security_node', '0004_auto_20180508_1830'),
    ]

    operations = [
        migrations.AlterField(
            model_name='group',
            name='group_name',
            field=models.CharField(error_messages={'unique': 'This group name has already been registered.'}, max_length=200, unique=True),
        ),
    ]
