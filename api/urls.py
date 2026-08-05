from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns

from api import views

# URL convention, every route matches exactly one of these shapes:
#   1. global collection  v1/<resource>/
#   2. project list       v1/project/<projectid>/<resource>/           (filters via query params)
#   3. item action        v1/project/<projectid>/<resource>/<id>/<action>/
#   4. bulk action        v1/project/<projectid>/<resource>/bulk/
#   5. operation group    v1/project/<projectid>/<group>/<action>/
# Literal segments are registered before parameterized ones so they win URL resolution.

urlpatterns = [

    ##### GLOBAL COLLECTIONS #####
    path('v1/projects/', views.projects, name='projects'),
    path('v1/keywords/add/', views.add_keyword, name='add_keyword'),
    path('v1/scheduled_jobs/', views.list_scheduled_jobs, name='list_scheduled_jobs'),

    ##### KEYWORDS #####
    path('v1/project/<str:projectid>/keywords/bulk_update/', views.bulk_update_keywords, name='bulk_update_keywords'),
    path('v1/project/<str:projectid>/keywords/', views.list_keywords, name='list_keywords'),

    ##### SUGGESTIONS #####
    path('v1/project/<str:projectid>/suggestions/bulk/', views.bulk_suggestions, name='bulk_suggestions'),
    path('v1/project/<str:projectid>/suggestions/', views.list_suggestions, name='list_suggestions'),

    ##### ASSETS #####
    path('v1/project/<str:projectid>/assets/bulk/', views.bulk_assets, name='bulk_assets'),
    path('v1/project/<str:projectid>/assets/', views.list_assets, name='list_assets'),
    path('v1/project/<str:projectid>/dns_records/', views.list_dns_records, name='list_dns_records'),
    path('v1/project/<str:projectid>/endpoints/', views.list_endpoints, name='list_endpoints'),
    path('v1/project/<str:projectid>/screenshots/', views.list_screenshots, name='list_screenshots'),

    ##### PORTS #####
    path('v1/project/<str:projectid>/ports/bulk/', views.bulk_ports, name='bulk_ports'),
    path('v1/project/<str:projectid>/ports/<str:portid>/delete/', views.delete_port, name='delete_port'),
    path('v1/project/<str:projectid>/ports/', views.list_ports, name='list_ports'),

    ##### FINDINGS #####
    path('v1/project/<str:projectid>/findings/bulk/', views.bulk_findings, name='bulk_findings'),
    path('v1/project/<str:projectid>/findings/<str:findingid>/delete/', views.delete_finding, name='delete_finding'),
    path('v1/project/<str:projectid>/findings/<str:findingid>/toggle_ignore/', views.toggle_finding_ignore, name='toggle_finding_ignore'),
    path('v1/project/<str:projectid>/findings/<str:findingid>/report/', views.report_finding, name='report_finding'),
    path('v1/project/<str:projectid>/findings/<str:findingid>/update_comment/', views.update_finding_comment, name='update_finding_comment'),
    path('v1/project/<str:projectid>/findings/', views.list_all_findings, name='list_all_findings'),

    ##### DATA LEAKS #####
    path('v1/project/<str:projectid>/data_leaks/bulk/', views.bulk_findings_data_leaks, name='bulk_findings_data_leaks'),
    path('v1/project/<str:projectid>/data_leaks/', views.list_data_leaks, name='list_data_leaks'),

    ##### JOBS #####
    path('v1/project/<str:projectid>/jobs/', views.list_jobs, name='list_jobs'),

    ##### ASSET SCANS #####
    path('v1/project/<str:projectid>/scans/preview/', views.scans_preview, name='scans_preview'),
    path('v1/project/<str:projectid>/scans/preselect/', views.scans_preselect, name='scans_preselect'),
    path('v1/project/<str:projectid>/scans/launch/', views.scans_launch, name='scans_launch'),
    path('v1/project/<str:projectid>/scans/burp/', views.scans_burp, name='scans_burp'),

    ##### KEYWORD DISCOVERY #####
    path('v1/project/<str:projectid>/discovery/launch/', views.discovery_launch, name='discovery_launch'),

    ##### DEPRECATED ALIASES (remove after one release) #####
    path('v1/keyword/add/', views.add_keyword_legacy, name='add_keyword_legacy'),
]

urlpatterns = format_suffix_patterns(urlpatterns)
