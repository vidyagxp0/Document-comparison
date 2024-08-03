from django.urls import path
from compareapp import views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginUser, name="login"),
    path('logout/', views.logoutUser, name="logout"),
    path('form/', views.form, name="form"),
    path('form/document-list', views.documentList, name="document-list"),
    path('comparison/', views.comparison, name="compare"),
    path('comparison/report/preview', views.preview, name="preview"),
    path('form/remove/<int:doc_id>/', views.removeDocument, name="remove-doc"),
    path('upload_pdf/', views.upload_pdf, name='upload_pdf'),
]
