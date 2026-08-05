from django.urls import path
from accounts import views

urlpatterns = [
    path('logout/', views.accounts_logout, name='logout'),
    path('login/', views.accounts_login, name='login'),
    path('change/password/', views.change_password, name='change_password'),
    path('api-key/', views.manage_api_key, name='api_key'),
]
