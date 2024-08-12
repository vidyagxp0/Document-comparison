# Generated by Django 5.0.7 on 2024-08-12 06:04

import compareapp.models
import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('compareapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='comparisonreport',
            name='comparison_date',
            field=models.DateField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name='comparisonreport',
            name='report_number',
            field=models.CharField(max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='comparisonreport',
            name='report_path',
            field=models.FileField(upload_to='comparison-reports/'),
        ),
        migrations.AlterField(
            model_name='document',
            name='upload_document',
            field=models.FileField(upload_to=compareapp.models.Document.upload_to_path),
        ),
        migrations.CreateModel(
            name='DocumentComparison',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='compareapp.document')),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='compareapp.comparisonreport')),
            ],
            options={
                'unique_together': {('report', 'document')},
            },
        ),
        migrations.AddField(
            model_name='comparisonreport',
            name='documents',
            field=models.ManyToManyField(related_name='comparison_reports', through='compareapp.DocumentComparison', to='compareapp.document'),
        ),
    ]