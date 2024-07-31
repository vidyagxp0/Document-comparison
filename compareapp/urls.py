from django.urls import path
from compareapp import views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginUser, name="login"),
    path('logout/', views.logoutUser, name="logout"),
    path('form/', views.form, name="form"),
    path('form/document-list', views.documentList, name="document-list"),
    path('comparison/report', views.comparison, name="compare"),
    path('form/remove/<int:doc_id>/', views.removeDocument, name="remove-doc"),
    # path('bulk-pdf/', views.bulkPDF, name="bulk-pdf"),
    # path('bulk-doc/', views.bulkDoc, name="bulk-doc"),
]
