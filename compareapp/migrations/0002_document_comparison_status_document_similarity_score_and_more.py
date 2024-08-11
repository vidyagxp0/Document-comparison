# Generated by Django 5.0.7 on 2024-08-11 20:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('compareapp', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='document',
            name='comparison_status',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='document',
            name='similarity_score',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='document',
            name='summary',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
