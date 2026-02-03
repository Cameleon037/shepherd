"""shepherd URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings

from shepherd import views

urlpatterns = [
    path('', views.home, name='home'),
    path('projects/', include(('project.urls', 'projects'), namespace='projects')),
    path('keywords/', include(('keywords.urls', 'keywords'), namespace='keywords')),
    path('suggestions/', include(('suggestions.urls', 'suggestions'), namespace='suggestions')),
    path('findings/', include(('findings.urls', 'findings'), namespace='findings')),
    path('dashboard/', include(('dashboard.urls', 'dashboard'), namespace='dashboard')),
    path('accounts/', include(('accounts.urls', 'accounts'), namespace='accounts')),
    path('api/', include(('api.urls', 'api'), namespace='api')),
    path('jobs/', include(('jobs.urls', 'jobs'), namespace='jobs')),
    path('oidc/', include('mozilla_django_oidc.urls')),
]

if settings.ADMIN_ENABLED:
    urlpatterns.append( path('admin/', admin.site.urls) )
