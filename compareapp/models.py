from django.db import models
from django.utils import timezone

class Document(models.Model):
    LANGUAGE_CHOICES = (
        ('af', 'Afrikaans'),
        ('ar', 'Arabic'),
        ('ar-dz', 'Algerian Arabic'),
        ('ast', 'Asturian'),
        ('az', 'Azerbaijani'),
        ('bg', 'Bulgarian'),
        ('be', 'Belarusian'),
        ('bn', 'Bengali'),
        ('br', 'Breton'),
        ('bs', 'Bosnian'),
        ('ca', 'Catalan'),
        ('ckb', 'Central Kurdish (Sorani)'),
        ('cs', 'Czech'),
        ('cy', 'Welsh'),
        ('da', 'Danish'),
        ('de', 'German'),
        ('dsb', 'Lower Sorbian'),
        ('el', 'Greek'),
        ('en', 'English'),
        ('en-au', 'Australian English'),
        ('en-gb', 'British English'),
        ('eo', 'Esperanto'),
        ('es', 'Spanish'),
        ('es-ar', 'Argentinian Spanish'),
        ('es-co', 'Colombian Spanish'),
        ('es-mx', 'Mexican Spanish'),
        ('es-ni', 'Nicaraguan Spanish'),
        ('es-ve', 'Venezuelan Spanish'),
        ('et', 'Estonian'),
        ('eu', 'Basque'),
        ('fa', 'Persian'),
        ('fi', 'Finnish'),
        ('fr', 'French'),
        ('fy', 'Frisian'),
        ('ga', 'Irish'),
        ('gd', 'Scottish Gaelic'),
        ('gl', 'Galician'),
        ('he', 'Hebrew'),
        ('hi', 'Hindi'),
        ('hr', 'Croatian'),
        ('hsb', 'Upper Sorbian'),
        ('hu', 'Hungarian'),
        ('hy', 'Armenian'),
        ('ia', 'Interlingua'),
        ('id', 'Indonesian'),
        ('ig', 'Igbo'),
        ('io', 'Ido'),
        ('is', 'Icelandic'),
        ('it', 'Italian'),
        ('ja', 'Japanese'),
        ('ka', 'Georgian'),
        ('kab', 'Kabyle'),
        ('kk', 'Kazakh'),
        ('km', 'Khmer'),
        ('kn', 'Kannada'),
        ('ko', 'Korean'),
        ('ky', 'Kyrgyz'),
        ('lb', 'Luxembourgish'),
        ('lt', 'Lithuanian'),
        ('lv', 'Latvian'),
        ('mk', 'Macedonian'),
        ('ml', 'Malayalam'),
        ('mn', 'Mongolian'),
        ('mr', 'Marathi'),
        ('ms', 'Malay'),
        ('my', 'Burmese'),
        ('nb', 'Norwegian Bokmål'),
        ('ne', 'Nepali'),
        ('nl', 'Dutch'),
        ('nn', 'Norwegian Nynorsk'),
        ('os', 'Ossetic'),
        ('pa', 'Punjabi'),
        ('pl', 'Polish'),
        ('pt', 'Portuguese'),
        ('pt-br', 'Brazilian Portuguese'),
        ('ro', 'Romanian'),
        ('ru', 'Russian'),
        ('sk', 'Slovak'),
        ('sl', 'Slovenian'),
        ('sq', 'Albanian'),
        ('sr', 'Serbian'),
        ('sr-latn', 'Serbian Latin'),
        ('sv', 'Swedish'),
        ('sw', 'Swahili'),
        ('ta', 'Tamil'),
        ('te', 'Telugu'),
        ('tg', 'Tajik'),
        ('th', 'Thai'),
        ('tk', 'Turkmen'),
        ('tr', 'Turkish'),
        ('tt', 'Tatar'),
        ('udm', 'Udmurt'),
        ('ug', 'Uyghur'),
        ('uk', 'Ukrainian'),
        ('ur', 'Urdu'),
        ('uz', 'Uzbek'),
        ('vi', 'Vietnamese'),
        ('zh-hans', 'Simplified Chinese'),
        ('zh-hant', 'Traditional Chinese')
    )

    DOC_TYPE_CHOICES = (
        ('stp', 'Standard Test Procedure'),
        ('sop', 'Standard Operating Procedure'),
        ('wi', 'Work Instruction'),
        ('spec', 'Specification'),
        ('vp', 'Validation Protocol'),
        ('pfd', 'Process Flow Diagram'),
        ('qp', 'Qualification Protocol'),
        ('sop_micro', 'Standard Operation Procedure for Microbiology'),
        ('sop_chem', 'Standard Operation Procedure for Chemistry/Wet Chemistry'),
        ('sop_instr', 'Standard Operation Procedure for Instrumental/Analytical Tests'),
        ('sop_equip', 'Standard Operation Procedure for Equipment/Instruments SOP'),
        ('qp', 'Quality Policies'),
        ('mv', 'Method Validation'),
        ('vp', 'Validation Protocol'),
        ('elec', 'Electron'),
    )

    # DOC_FORMAT_CHOICES = (
    #     ('pdf', 'PDF'),
    #     ('docx', 'Word Document (.docx)'),
    #     ('xlsx', 'Spreadsheet'),
    #     ('pptx', 'Presentation'),
    #     ('vsd', 'Visio File'),
    #     ('mp3', 'Audio (.mp3)'),
    #     ('mp4', 'Video (.mp4)'),
    #     ('png', 'Image File'),
    #     ('txt', 'Text File'),
    #     ('other', 'Other'),
    # )

    def upload_to_path(instance, filename):
        format_paths = {
            'pdf': 'documents/pdf/',
            'docx': 'documents/docx/',
            'xlsx': 'documents/excel/',
            'pptx': 'documents/ppt/',
            'txt': 'documents/text/',
            'other': 'documents/other/',
        }
        return f"{format_paths.get(instance.doc_format, 'documents/other/')}{filename}"

    document_id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    creation_date = models.DateField(default=timezone.now)
    upload_document = models.FileField(upload_to=upload_to_path)
    language = models.CharField(max_length=255, choices=LANGUAGE_CHOICES, default='en')
    version = models.CharField(max_length=255, default='1.0.0')
    doc_type = models.CharField(max_length=255, choices=DOC_TYPE_CHOICES, default='stp')
    # doc_format = models.CharField(max_length=255, choices=DOC_FORMAT_CHOICES)
    doc_format = models.CharField(max_length=255)
    comments = models.TextField()
    comparison_status = models.CharField(max_length=255, null=True, blank=True)
    summary = models.CharField(max_length=255, null=True, blank=True)
    similarity_score = models.FloatField(null=True, blank=True)
    report_number = models.CharField(max_length=255, null=True, blank=True)
    new = models.BooleanField(default=True)
    comparison_between = models.CharField(max_length=255, default=None)

    def __str__(self):
        return self.title

class ComparisonReport(models.Model):
    report_number = models.CharField(max_length=255, unique=True)
    comparison_reason = models.CharField(max_length=255)
    compared_documents = models.JSONField()
    comparison_summary = models.JSONField()
    comparison_date = models.DateField(default=timezone.now)
    compared_by = models.CharField(max_length=255)
    report_path = models.TextField()
    comparison_between = models.CharField(max_length=255, default=None)


    def __str__(self):
        return self.comparison_reason

class Feedback(models.Model):
    feedback = models.TextField()
    email = models.EmailField(blank=True, null=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback from {self.email or 'Anonymous'}"