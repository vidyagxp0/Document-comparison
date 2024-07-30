from django.db import models
from django.utils import timezone

class Document(models.Model):
    document_id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    creation_date = models.DateField(default=timezone.now)
    upload_document = models.FileField(upload_to='documents/')
    language = models.CharField(max_length=255)
    version = models.CharField(max_length=255)
    doc_type = models.CharField(max_length=255)
    doc_format = models.CharField(max_length=255)
    comments = models.TextField()

    def __str__(self):
        return self.title

class ComparisonResult(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    comparison_status = models.CharField(max_length=255)
    similarity_score = models.FloatField()
    summary = models.TextField()

    def __str__(self):
        return f"Comparison Result for {self.document.title} - Status: {self.comparison_status}"
