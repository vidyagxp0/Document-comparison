# Generated by Django 5.0.7 on 2024-09-03 14:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('compareapp', '0002_alter_document_doc_format'),
    ]

    operations = [
        migrations.AddField(
            model_name='comparisonreport',
            name='comparison_status',
            field=models.BooleanField(default=True),
        ),
    ]
