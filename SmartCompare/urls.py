from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

admin.site.site_header = "Document Comparison Pro"
admin.site.site_title = "Welcome to our Software Services"
admin.site.index_title = "Admin Panel"

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('compareapp.urls')),
    path("__reload__/", include("django_browser_reload.urls")),
    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

