from django.contrib import admin
from compareapp.models import Document, ComparisonReport, Feedback

# prepare list for admin panel
class DocumentAdmin(admin.ModelAdmin):
    list_display = ('user', 'report_number', 'comparison_between')


admin.site.register(Document, DocumentAdmin)
admin.site.register(ComparisonReport)
admin.site.register(Feedback)
