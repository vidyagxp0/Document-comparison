# Generated by Django 5.0.7 on 2024-08-11 21:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('compareapp', '0002_document_comparison_status_document_similarity_score_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ComparisonReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_number', models.CharField(max_length=255)),
                ('comparison_reason', models.CharField(max_length=255)),
                ('compared_documents', models.JSONField()),
                ('comparison_summary', models.JSONField()),
                ('comparison_date', models.DateField()),
                ('compared_by', models.CharField(max_length=255)),
                ('report_path', models.TextField()),
            ],
        ),
        migrations.AddField(
            model_name='document',
            name='new',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='document',
            name='report_number',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
