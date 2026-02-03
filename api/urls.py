from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from api import views

urlpatterns = [

    # project APIs
    path('v1/projects/', views.list_projects, name='list_projects'),
    path('v1/project/create/', views.create_project, name='create_project'),
    path('v1/project/<str:projectid>/keywords/<str:selection>/', views.list_keywords, name='list_keywords'),
    path('v1/project/<str:projectid>/suggestions/<str:selection>/<str:vtype>/', views.list_suggestions, name='list_suggestions'),
    path('v1/project/<str:projectid>/assets/<str:selection>/', views.list_assets, name='list_assets'),
    path('v1/project/<str:projectid>/dns_records/', views.list_dns_records, name='list_dns_records'),
    path('v1/project/<str:projectid>/endpoints/', views.list_endpoints, name='list_endpoints'),
    path('v1/project/<str:projectid>/screenshots/', views.list_screenshots, name='list_screenshots'),
    #path('v1/project/<str:projectid>/modify/', views.modify_project, name='modify_project'),
    #path('v1/project/<str:projectid>/delete/', views.delete_project, name='delete_project'),

    # keyword APIs
    path('v1/keyword/add/', views.add_keyword, name='add_keyword'),

    # ports APIs
    path('v1/project/<str:projectid>/ports/', views.list_ports, name='list_ports'),
    path('v1/project/<str:projectid>/ports/<str:portid>/delete/', views.delete_port, name='delete_port'),

    # Findings APIs
    path('v1/project/<str:projectid>/findings/all/', views.list_all_findings, name='list_all_findings'),
    path('v1/project/<str:projectid>/findings/data_leaks/', views.list_data_leaks, name='list_data_leaks'),
    path('v1/project/<str:projectid>/findings/delete/<str:findingid>/', views.delete_finding, name='delete_finding'),
    path('v1/project/<str:projectid>/findings/<str:findingid>/update_comment/', views.update_finding_comment, name='update_finding_comment'),
    # path('v1/project/<str:projectid>/recent/<str:severity>/', views.list_recent_findings, name='list_recent_findings'),

    # Jobs
    path('v1/scheduled_jobs/', views.list_scheduled_jobs, name='list_scheduled_jobs'),
    path('v1/project/<str:projectid>/jobs/all/', views.list_jobs, name='list_jobs'),
]

urlpatterns = format_suffix_patterns(urlpatterns)
