from django.db.models import Q
from project.models import Asset, Project
from django.http import HttpResponse
import csv


def export_assets_csv(project_id, monitored_only=False, scope='external'):
    """
    Export assets to CSV format.
    
    Args:
        project_id: Project ID to filter assets
        monitored_only: If True, only export monitored assets. If False, export all assets.
        scope: Scope filter (default: 'external')
    
    Returns:
        HttpResponse: CSV file response
    """
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return HttpResponse("Project not found", status=404)
    
    # Build queryset
    queryset = Asset.objects.filter(related_project=project, scope=scope)
    
    # Filter by monitor status if specified
    if monitored_only:
        queryset = queryset.filter(monitor=True, ignore=False)
    else:
        queryset = queryset.filter(ignore=False)
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    filename = "monitored_assets.csv" if monitored_only else "suggestions.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    writer = csv.writer(response)
    # Write header
    writer.writerow([
        'UUID', 'Value', 'Related Project', 'Related Keyword', 'Type', 'Subtype',
        'Source', 'Description', 'Link', 'Creation Time', 'Active', 'Ignore', 'Monitor', 'Redirects To', 'Scope',
        'IPv4', 'IPv6', 'Owner'
    ])
    # Write data rows
    for asset in queryset:
        writer.writerow([
            asset.uuid,
            asset.value,
            asset.related_project.projectname if asset.related_project else '',
            asset.related_keyword.keyword if asset.related_keyword else '',
            asset.type,
            asset.subtype,
            asset.source,
            asset.description,
            asset.link,
            asset.creation_time,
            asset.active,
            asset.ignore,
            asset.monitor,
            asset.redirects_to.value if asset.redirects_to else '',
            asset.scope,
            asset.ipv4,
            asset.ipv6,
            asset.owner,
        ])
    return response


def auto_monitor_trusted_assets(project_id):
    """
    Automatically monitor assets that:
    1) Are of type "domain" or "ip"
    2) Are not ignored (ignore=False)
    3) Are active (active=True)
    4) Are not monitored (monitor=False)
    5) Come from a "trusted" source (subfinder, domaintools, file_upload)
    
    Args:
        project_id: Project ID. Only processes assets for this project.
    
    Returns:
        tuple: (count_updated, list_of_updated_assets)
    """
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return 0, []
    
    # Trusted sources
    trusted_sources = ['subfinder', 'domaintools', 'file_upload']
    
    # Build Q objects for source filtering (check if source contains any trusted source)
    source_filters = Q()
    for source in trusted_sources:
        source_filters |= Q(source__icontains=source)
    
    # Base queryset filters (only domain and ip assets)
    queryset = Asset.objects.filter(
        related_project=project,
        type__in=['domain', 'ip'],
        ignore=False,      # Not ignored
        active=True,       # Active
        monitor=False,     # Not monitored
    ).filter(source_filters)  # From trusted sources
    
    # Get assets to update
    assets_to_update = list(queryset)
    
    # Update monitor flag for all matching assets
    count = queryset.update(monitor=True)
    
    return count, assets_to_update


def auto_unmonitor_assets(project_id):
    """
    Automatically unmonitor assets that:
    1) Are currently monitored (monitor=True)
    2) Are inactive (active=False)
    
    Args:
        project_id: Project ID. Only processes assets for this project.
    
    Returns:
        tuple: (count_updated, list_of_updated_assets)
    """
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return 0, []
    
    # Find monitored assets that are inactive
    queryset = Asset.objects.filter(
        related_project=project,
        monitor=True,      # Currently monitored
        active=False,      # Inactive
    )
    
    # Get assets to update
    assets_to_update = list(queryset)
    
    # Update monitor flag to False for all matching assets
    count = queryset.update(monitor=False)
    
    return count, assets_to_update
