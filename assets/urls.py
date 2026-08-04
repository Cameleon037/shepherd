from django.urls import path
from assets import views

urlpatterns = [
    path('', views.suggestions, name='suggestions'),
    path('scan_suggestions/', views.scan_suggestions, name='scan_suggestions'),
    path('export/', views.export_suggestions_csv, name='export'),
    path('ignored/', views.ignored_suggestions, name='ignored_suggestions'),
    path('manual/add/', views.manual_add_suggestion, name='manual_add_suggestion'),
    # path('recent/', views.recent_suggestions, name='recent_suggestions'),
    # path('ignore/star/', views.ignore_star_suggestions, name='ignore_star_suggestions'),
    path('ignore/<str:uuid>/', views.ignore_suggestion, name='ignore_suggestion'),
    path('monitor/<str:uuid>/', views.monitor_suggestion, name='monitor_suggestion'),
    # path('monitor/all/unique/', views.monitor_all_unique_domains, name='monitor_all_unique_domains'),
    path('reactivate/<str:uuid>/', views.reactivate_suggestion, name='reactivate_suggestion'),
    path('delete/<str:uuid>/', views.delete_suggestion, name='delete_suggestion'),
    path('delete/<str:uuid>/ignored/', views.delete_suggestion_ignored, name='delete_suggestion_ignored'),
    path('all/delete/', views.delete_all_suggestions, name='delete_all_suggestions'),
    path('upload_suggestions/', views.upload_suggestions, name='upload_suggestions'),

    # Monitored asset inventory (moved from findings)
    path('inventory/', views.assets, name='assets'),
    path('inventory/move/all/', views.move_all_assets, name='move_all_assets'),
    path('inventory/move/<str:uuid>/', views.move_asset, name='move_asset'),
    path('inventory/delete/<str:uuid>/', views.delete_asset, name='delete_asset'),
    path('inventory/activate/all/', views.activate_all_assets, name='activate_all_assets'),
    path('inventory/activate/<str:uuid>/', views.activate_asset, name='activate_asset'),
    path('inventory/view/<str:uuid>/', views.view_asset, name='view_asset'),
    path('inventory/ignore/<str:uuid>/', views.ignore_asset_glyphicon, name='ignore_asset_glyphicon'),
    path('inventory/manual/add/', views.manual_add_asset, name='manual_add_asset'),
    path('inventory/upload/', views.upload_assets, name='upload_assets'),
    path('inventory/export/', views.export_monitored_assets_csv, name='export_monitored_assets_csv'),
]
