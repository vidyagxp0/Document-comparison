from django.urls import path
from compareapp import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginUser, name="login"),
    path('logout/', views.logoutUser, name="logout"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('feedback/', views.submitFeedback, name="feedback"),

    # User Management system
    path('user-management/', views.userManagement, name='user-management'),

    # Route to add a new user
    path('users/add/', views.add_edit_user, name='add-user'),

    # Route to edit an existing user
    path('users/edit/<int:user_id>/', views.add_edit_user, name='edit-user'),
    path('users/delete/<int:user_id>/', views.delete_user, name='delete-user'),
    path('users/profile/<int:user_id>/', views.user_profile, name='user-profile'),

    # View analytics
    path('analytics', views.analytics, name="analytics"),   


    # For Document upload
    path('form/', views.formView, name="form"),
    path('form/view/<int:doc_id>/', views.documentDetail, name="view-document"),
    path('form/initial-documents', views.initialDocument, name="initial-document"),
    path('form/remove/<int:doc_id>/', views.removeDocument, name="remove-doc"),
    
    # For comparison
    path('comparison/view/<str:report_id>', views.viewComparison, name="view-comparison"),
    path('comparison/', views.comparison, name="compare"),
    path('comparison/preview/<str:report>', views.preview, name="preview"),

    # To chatPDF
    path('upload-pdf/', views.uploadPDF, name='upload-pdf'),
    path('proxy-chat-pdf/', views.proxy_chat_pdf, name='proxy-chat-pdf'),

    # Password Resetting
    path('password_reset/', views.password_reset_request, name='password_reset'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),

]
