# Generated by Django 5.0.7 on 2024-09-12 12:30

import compareapp.models
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Feedback',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feedback', models.TextField()),
                ('email', models.EmailField(blank=True, max_length=254, null=True)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.CreateModel(
            name='ComparisonReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_number', models.CharField(max_length=255, unique=True)),
                ('comparison_reason', models.CharField(max_length=255)),
                ('compared_documents', models.JSONField()),
                ('comparison_summary', models.JSONField()),
                ('comparison_date', models.DateField(default=django.utils.timezone.now)),
                ('compared_by', models.CharField(max_length=255)),
                ('comparison_status', models.BooleanField(default=True)),
                ('report_path', models.TextField()),
                ('comparison_between', models.CharField(default=None, max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Document',
            fields=[
                ('document_id', models.AutoField(primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255)),
                ('author', models.CharField(max_length=255)),
                ('creation_date', models.DateField(default=django.utils.timezone.now)),
                ('upload_document', models.FileField(upload_to=compareapp.models.Document.upload_to_path)),
                ('language', models.CharField(choices=[('af', 'Afrikaans'), ('ar', 'Arabic'), ('ar-dz', 'Algerian Arabic'), ('ast', 'Asturian'), ('az', 'Azerbaijani'), ('bg', 'Bulgarian'), ('be', 'Belarusian'), ('bn', 'Bengali'), ('br', 'Breton'), ('bs', 'Bosnian'), ('ca', 'Catalan'), ('ckb', 'Central Kurdish (Sorani)'), ('cs', 'Czech'), ('cy', 'Welsh'), ('da', 'Danish'), ('de', 'German'), ('dsb', 'Lower Sorbian'), ('el', 'Greek'), ('en', 'English'), ('en-au', 'Australian English'), ('en-gb', 'British English'), ('eo', 'Esperanto'), ('es', 'Spanish'), ('es-ar', 'Argentinian Spanish'), ('es-co', 'Colombian Spanish'), ('es-mx', 'Mexican Spanish'), ('es-ni', 'Nicaraguan Spanish'), ('es-ve', 'Venezuelan Spanish'), ('et', 'Estonian'), ('eu', 'Basque'), ('fa', 'Persian'), ('fi', 'Finnish'), ('fr', 'French'), ('fy', 'Frisian'), ('ga', 'Irish'), ('gd', 'Scottish Gaelic'), ('gl', 'Galician'), ('he', 'Hebrew'), ('hi', 'Hindi'), ('hr', 'Croatian'), ('hsb', 'Upper Sorbian'), ('hu', 'Hungarian'), ('hy', 'Armenian'), ('ia', 'Interlingua'), ('id', 'Indonesian'), ('ig', 'Igbo'), ('io', 'Ido'), ('is', 'Icelandic'), ('it', 'Italian'), ('ja', 'Japanese'), ('ka', 'Georgian'), ('kab', 'Kabyle'), ('kk', 'Kazakh'), ('km', 'Khmer'), ('kn', 'Kannada'), ('ko', 'Korean'), ('ky', 'Kyrgyz'), ('lb', 'Luxembourgish'), ('lt', 'Lithuanian'), ('lv', 'Latvian'), ('mk', 'Macedonian'), ('ml', 'Malayalam'), ('mn', 'Mongolian'), ('mr', 'Marathi'), ('ms', 'Malay'), ('my', 'Burmese'), ('nb', 'Norwegian Bokmål'), ('ne', 'Nepali'), ('nl', 'Dutch'), ('nn', 'Norwegian Nynorsk'), ('os', 'Ossetic'), ('pa', 'Punjabi'), ('pl', 'Polish'), ('pt', 'Portuguese'), ('pt-br', 'Brazilian Portuguese'), ('ro', 'Romanian'), ('ru', 'Russian'), ('sk', 'Slovak'), ('sl', 'Slovenian'), ('sq', 'Albanian'), ('sr', 'Serbian'), ('sr-latn', 'Serbian Latin'), ('sv', 'Swedish'), ('sw', 'Swahili'), ('ta', 'Tamil'), ('te', 'Telugu'), ('tg', 'Tajik'), ('th', 'Thai'), ('tk', 'Turkmen'), ('tr', 'Turkish'), ('tt', 'Tatar'), ('udm', 'Udmurt'), ('ug', 'Uyghur'), ('uk', 'Ukrainian'), ('ur', 'Urdu'), ('uz', 'Uzbek'), ('vi', 'Vietnamese'), ('zh-hans', 'Simplified Chinese'), ('zh-hant', 'Traditional Chinese')], default='en', max_length=255)),
                ('version', models.CharField(default='1.0.0', max_length=255)),
                ('doc_type', models.CharField(choices=[('stp', 'Standard Test Procedure'), ('sop', 'Standard Operating Procedure'), ('wi', 'Work Instruction'), ('spec', 'Specification'), ('vp', 'Validation Protocol'), ('pfd', 'Process Flow Diagram'), ('qp', 'Qualification Protocol'), ('sop_micro', 'Standard Operation Procedure for Microbiology'), ('sop_chem', 'Standard Operation Procedure for Chemistry/Wet Chemistry'), ('sop_instr', 'Standard Operation Procedure for Instrumental/Analytical Tests'), ('sop_equip', 'Standard Operation Procedure for Equipment/Instruments SOP'), ('qp', 'Quality Policies'), ('mv', 'Method Validation'), ('vp', 'Validation Protocol'), ('elec', 'Electron')], default='stp', max_length=255)),
                ('doc_format', models.CharField(max_length=255)),
                ('comments', models.TextField()),
                ('comparison_status', models.CharField(blank=True, max_length=255, null=True)),
                ('summary', models.CharField(blank=True, max_length=255, null=True)),
                ('similarity_score', models.FloatField(blank=True, null=True)),
                ('report_number', models.CharField(blank=True, max_length=255, null=True)),
                ('new', models.BooleanField(default=True)),
                ('comparison_between', models.CharField(default=None, max_length=255)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
