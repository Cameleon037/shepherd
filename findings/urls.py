from django.urls import path
from findings import views

urlpatterns = [
    # Assets stuffs
    path('', views.assets, name='assets'),
    path('ignore/<str:findingid>/', views.ignore_finding_glyphicon, name='ignore_finding_glyphicon'),
    path('move/all/', views.move_all_assets, name='move_all_assets'),
    path('move/<str:uuid>/', views.move_asset, name='move_asset'),
    path('delete/<str:uuid>/', views.delete_asset, name='delete_asset'),
    path('activate/all/', views.activate_all_assets, name='activate_all_assets'),
    path('activate/<str:uuid>/', views.activate_asset, name='activate_asset'),
    path('view/<str:uuid>/', views.view_asset, name='view_asset'),

    # Asset stuffs
    path('asset/<str:uuid>/finding/<str:findingid>/delete/', views.delete_finding, name='delete_finding'),
    path('asset/ignore/<str:uuid>/', views.ignore_asset_glyphicon, name='ignore_asset_glyphicon'),

    # Nucleus stuffs
    path('send/nucleus/<str:findingid>/', views.send_nucleus, name='send_nucleus'),

    # Nmap stuffs
    path('nmap/results/', views.nmap_results, name='nmap_results'),

    # HTTPX Results
    path('httpx/results/', views.httpx_results, name='httpx_results'),
    path('control-center/', views.control_center, name='control_center'),
    path('control-center/preview/', views.control_center_preview, name='control_center_preview'),
    path('control-center/launch/', views.control_center_launch, name='control_center_launch'),
    path('technologies/export/', views.export_technologies_csv, name='export_technologies_csv'),

    # Scanner stuffs
    path('scan_assets/', views.scan_assets, name='scan_assets'),
    path('scanners/results', views.all_findings, name='all_findings'),

    # Data leakage stuffs
    path('data_leaks/', views.data_leaks, name='data_leaks'),
    
    # Manual asset management
    path('manual/add/', views.manual_add_asset, name='manual_add_asset'),
    path('upload_assets/', views.upload_assets, name='upload_assets'),
    
    # DNS records
    path('dns_records/', views.dns_records, name='dns_records'),
    path('dns_records/export/', views.export_dns_records_csv, name='export_dns_records_csv'),
    
    # Web endpoints
    path('web_endpoints/', views.web_endpoints, name='web_endpoints'),
    path('web_endpoints/export/', views.export_web_endpoints_csv, name='export_web_endpoints_csv'),
    
    # Asset export
    path('assets/export/', views.export_monitored_assets_csv, name='export_monitored_assets_csv'),
]
