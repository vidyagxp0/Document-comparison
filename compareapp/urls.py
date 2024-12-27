from django.urls import path
from compareapp import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.loginUser, name="login"),
    path('logout/', views.logoutUser, name="logout"),
    path('dashboard/', views.dashboard, name="dashboard"),
    path('feedback/', views.submitFeedback, name="feedback"),
    path('software/org-documentation/', views.softwareDocumentation, name="documentation"),

    # User Management system
    path('user-management/users/', views.userManagement, name='user-management'),
    path('user-management/users/add/', views.add_edit_user, name='add-user'),
    path('user-management/user/edit/<int:user_id>/', views.add_edit_user, name='edit-user'),
    path('user-management/user/delete/<int:user_id>/', views.delete_user, name='delete-user'),
    path('user-management/user/profile/<int:user_id>/', views.user_profile, name='user-profile'),
    path('user-management/user-logs', views.userLogs, name='user-logs'),

    # View analytics
    path('analytics/', views.analytics, name="analytics"),  

    # For Document upload
    path('upload-documents/', views.formView, name="form"),
    path('form/reset', views.cancelComparison, name="cancel-comparison"),  
    path('form/view/<int:doc_id>/', views.documentDetail, name="view-document"),
    path('form/compared-documents/<str:id>', views.comparedDocument, name="compared-documents"),
    path('form/remove/<int:doc_id>/', views.removeDocument, name="remove-doc"),
    path('form/import-data/', views.importData, name="import-data"),  
    
    # For comparison
    path('comparison/view/<str:report_id>', views.viewComparison, name="view-comparison"),
    path('comparison/', views.comparison, name="compare"),
    path('comparison/preview/<str:report>', views.preview, name="preview"),

    # For chatPDF
    path('upload-pdf/', views.uploadPDF, name='upload-pdf'),
    path('proxy-chat-pdf/', views.proxy_chat_pdf, name='proxy-chat-pdf'),

    # Password resetting
    path('password-reset/', views.password_reset_request, name='password_reset'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='password-base/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password-base/password_reset_complete.html'), name='password_reset_complete'),

    # Password Creation
    path('password-creation/<uidb64>/<token>/', views.password_creation_view, name='password_create'),
    path('password-creation/done/', auth_views.PasswordResetDoneView.as_view(template_name='password-base/password_create_done.html'), name='password_create_done'),


]
