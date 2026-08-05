from django.urls import path
from findings import views

urlpatterns = [
    # Findings
    path('', views.all_findings, name='home'),
    path('asset/<str:uuid>/finding/<str:findingid>/delete/', views.delete_finding, name='delete_finding'),

    # Nmap stuffs
    path('nmap/results/', views.nmap_results, name='nmap_results'),

    # HTTPX Results
    path('httpx/results/', views.httpx_results, name='httpx_results'),
    path('control-center/', views.control_center, name='control_center'),
    path('technologies/export/', views.export_technologies_csv, name='export_technologies_csv'),

    # Scanner stuffs
    path('scanners/results', views.all_findings, name='all_findings'),

    # Data leakage stuffs
    path('data_leaks/', views.data_leaks, name='data_leaks'),

    # DNS records
    path('dns_records/', views.dns_records, name='dns_records'),
    path('dns_records/export/', views.export_dns_records_csv, name='export_dns_records_csv'),

    # Web endpoints
    path('web_endpoints/', views.web_endpoints, name='web_endpoints'),
    path('web_endpoints/export/', views.export_web_endpoints_csv, name='export_web_endpoints_csv'),
]
