from django.urls import path
from compareapp import views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginUser, name="login"),
    path('form/', views.form, name="form"),
]
