from django.urls import path
from compareapp import views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginUser, name="login"),
    path('logout/', views.logoutUser, name="logout"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('form/', views.form, name="form"),
    path('form/view/<int:doc_id>/', views.documentDetail, name="view-document"),
    path('form/document-list', views.documentList, name="document-list"),
    path('comparison/', views.comparison, name="compare"),
    path('comparison/report/preview', views.preview, name="preview"),
    path('form/remove/<int:doc_id>/', views.removeDocument, name="remove-doc"),
    path('upload-pdf/', views.uploadPDF, name='upload-pdf'),
    path('proxy-chat-pdf/', views.proxy_chat_pdf, name='proxy-chat-pdf'),
]
