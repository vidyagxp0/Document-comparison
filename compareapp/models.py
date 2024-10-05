from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(
        max_length=15,
        blank=True,
        null=True
    )
    address = models.TextField(blank=True, null=True)
    department = models.CharField(max_length=50, blank=True, null=True)
    blood_group = models.CharField(max_length=3, blank=True, null=True)
    image = models.ImageField(upload_to='user_images/', default="user_images/user.png")

    def __str__(self):
        return self.user.username

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

    def upload_to_path(instance, filename):
        format_paths = {
            'pdf': 'documents/pdf/',
            'docx': 'documents/docx/',
            'xlsx': 'documents/excel/',
            'png': 'documents/images/',
            'wav': 'documents/audios/',
            'pptx': 'documents/ppt/',
            'txt': 'documents/text/',
            'other': 'documents/other/',
        }
        return f"{format_paths.get(instance.comparison_between, 'documents/other/')}{filename}"

    document_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_date = models.DateField(default=timezone.now)
    upload_documents = models.FileField(upload_to=upload_to_path)
    comparison_status = models.CharField(max_length=255, null=True, blank=True)
    summary = models.CharField(max_length=255, null=True, blank=True)
    similarity_score = models.FloatField(null=True, blank=True)
    report_number = models.CharField(max_length=255, null=True, blank=True)
    ai_summary = models.TextField(null=True, blank=True)
    new = models.BooleanField(default=True)
    comparison_between = models.CharField(max_length=255, default=None)


    def __str__(self):
        return self.comparison_between

class ComparisonReport(models.Model):
    report_number = models.CharField(max_length=255, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    compared_documents = models.JSONField(null=True, blank=True)
    comparison_summary = models.JSONField(null=True, blank=True)
    ai_summary = models.TextField(null=True, blank=True)
    comparison_date = models.DateField(default=timezone.now)
    compared_by = models.CharField(max_length=255, null=True, blank=True)
    comparison_status = models.BooleanField(default=True)
    report_path = models.TextField(null=True, blank=True)
    comparison_between = models.CharField(max_length=255, default=None, null=True, blank=True)

    short_description = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(max_length=400, null=True, blank=True)
    department_type = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.short_description

class UserLogs(models.Model):
    action = models.CharField(max_length=255, null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    action_type = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateTimeField(auto_now_add=True)
    done_by = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.done_by}'s Activities"


class Feedback(models.Model):
    feedback = models.TextField()
    email = models.EmailField(blank=True, null=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback from {self.email or 'Anonymous'}"