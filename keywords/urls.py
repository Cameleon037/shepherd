from django.urls import path
from keywords import views

urlpatterns = [
    path('', views.keywords, name='keywords'),
    path('add/', views.add_keyword, name='add_keyword'),

    path('scan_keywords/', views.scan_keywords, name='scan_keywords'),
    path('mine_keywords/', views.mine_keywords, name='mine_keywords'),
    path('control-center/', views.discovery_control_center, name='discovery_control_center'),
    path('upload-ransomlook-suppliers/', views.upload_ransomlook_suppliers, name='upload_ransomlook_suppliers'),
]

