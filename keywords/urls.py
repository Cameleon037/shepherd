from django.urls import path
from keywords import views

urlpatterns = [
    path('', views.keywords, name='keywords'),
    path('add/', views.add_keyword, name='add_keyword'),

    path('scan_keywords/', views.scan_keywords, name='scan_keywords'),
    path('control-center/', views.discovery_control_center, name='discovery_control_center'),
    path('upload-ransomlook-suppliers/', views.upload_ransomlook_suppliers, name='upload_ransomlook_suppliers'),

    path('<int:keywordid>/toggle/', views.toggle_keyword, name='toggle_keyword'),
    path('<int:keywordid>/delete/', views.delete_keyword, name='delete_keyword'),
]

