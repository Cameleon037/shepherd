from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden, StreamingHttpResponse
from project.models import Project
from assets.models import Asset
from findings.models import Port, Screenshot, Endpoint, DNSRecord
import csv
import json


### Nmap stuffs
@login_required
def nmap_results(request):
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission.")
    context = {'projectid': request.session['current_project']['prj_id']}
    return render(request, 'findings/list_nmap_results.html', context)


### Scanners stuffs
@login_required
def all_findings(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    context = {'projectid': request.session['current_project']['prj_id']}
    return render(request, 'findings/list_findings.html', context)

@login_required
def delete_finding(request, uuid, findingid):
    """delete a finding
    """
    if not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('assets:assets'))
    a_obj.finding_set.filter(id=findingid).delete() 
    messages.info(request, 'finding deleted!')
    return redirect(reverse('assets:view_asset', args=(uuid,)))

@login_required
def httpx_results(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    context = {
        'projectid': request.session.get('current_project', {}).get('prj_id', None),
    }

    return render(request, 'findings/list_screenshots.html', context)

@login_required
def control_center(request):
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    project_id = request.session.get('current_project', {}).get('prj_id', None)
    source_options = []
    if project_id:
        raw_sources = (
            Asset.objects.filter(related_project_id=project_id)
            .exclude(source__isnull=True)
            .exclude(source__exact='')
            .values_list('source', flat=True)
            .distinct()
        )
        unique_sources = set()
        for entry in raw_sources:
            parts = [part.strip() for part in entry.split(',') if part.strip()]
            unique_sources.update(parts)
        source_options = sorted(unique_sources)

    # Check if assets were pre-selected from the inventory
    preselected_uuids = request.session.pop('scan_selected_uuids', None) or []

    context = {
        'projectid': project_id,
        'source_options': source_options,
        'preselected_uuids': json.dumps(preselected_uuids),
        'preselected_count': len(preselected_uuids),
    }
    return render(request, 'findings/control_center.html', context)


@login_required
def export_technologies_csv(request):
    """Export all Screenshot objects as CSV with technologies info."""
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")

    # Get current project id from session
    projectid = request.session.get('current_project', {}).get('prj_id', None)
    if not projectid:
        return HttpResponseForbidden("No project selected.")
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return HttpResponseForbidden("Project does not exist.")

    # Get all screenshots for the project
    domains = prj.asset_set.all()
    screenshots = Port.objects.none()    
    screenshots = Screenshot.objects.filter(asset__in=domains).order_by('-date')

    # Prepare CSV response
    def screenshot_row(s):
        return [
            s.url,
            s.technologies,
            s.title,
            s.status_code,
            s.webserver,
            s.date.strftime('%Y-%m-%d %H:%M:%S') if s.date else '',
        ]

    class Echo:
        def write(self, value):
            return value

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    header = ['URL', 'Technologies', 'Title', 'Status Code', 'Webserver', 'Date']
    rows = (screenshot_row(s) for s in screenshots)
    response = StreamingHttpResponse(
        (writer.writerow(row) for row in ([header] + list(rows))),
        content_type="text/csv"
    )
    response['Content-Disposition'] = 'attachment; filename="httpx_technologies.csv"'
    return response

@login_required
def export_dns_records_csv(request):
    """Export all DNS records as CSV."""
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")

    # Get current project id from session
    projectid = request.session.get('current_project', {}).get('prj_id', None)
    if not projectid:
        return HttpResponseForbidden("No project selected.")
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return HttpResponseForbidden("Project does not exist.")

    # Get all DNS records for the project
    dns_records = DNSRecord.objects.filter(related_project=prj).select_related('related_asset').order_by('-last_checked')

    # Prepare CSV response
    def dns_row(record):
        return [
            record.related_asset.value,
            record.record_type,
            record.record_value,
            record.ttl if record.ttl else '',
            record.last_checked.strftime('%Y-%m-%d %H:%M:%S') if record.last_checked else '',
        ]

    class Echo:
        def write(self, value):
            return value

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    header = ['Asset', 'Record Type', 'Record Value', 'TTL', 'Last Checked']
    rows = (dns_row(r) for r in dns_records)
    response = StreamingHttpResponse(
        (writer.writerow(row) for row in ([header] + list(rows))),
        content_type="text/csv"
    )
    response['Content-Disposition'] = 'attachment; filename="dns_records.csv"'
    return response

@login_required
def export_web_endpoints_csv(request):
    """Export all web endpoints as CSV."""
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")

    # Get current project id from session
    projectid = request.session.get('current_project', {}).get('prj_id', None)
    if not projectid:
        return HttpResponseForbidden("No project selected.")
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return HttpResponseForbidden("Project does not exist.")

    # Get all endpoints for the project
    endpoints = Endpoint.objects.filter(asset__related_project=prj).select_related('asset').order_by('-date')

    # Prepare CSV response
    def endpoint_row(endpoint):
        return [
            endpoint.asset.value if endpoint.asset else '',
            endpoint.url,
            endpoint.technologies if endpoint.technologies else '',
            endpoint.date.strftime('%Y-%m-%d %H:%M:%S') if endpoint.date else '',
        ]

    class Echo:
        def write(self, value):
            return value

    pseudo_buffer = Echo()
    writer = csv.writer(pseudo_buffer)
    header = ['Asset', 'URL', 'Technologies', 'Date']
    rows = (endpoint_row(e) for e in endpoints)
    response = StreamingHttpResponse(
        (writer.writerow(row) for row in ([header] + list(rows))),
        content_type="text/csv"
    )
    response['Content-Disposition'] = 'attachment; filename="web_endpoints.csv"'
    return response

@login_required
def data_leaks(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    context = {'projectid': request.session['current_project']['prj_id']}
    return render(request, 'findings/list_data_leaks.html', context)


@login_required
def dns_records(request):
    """View DNS records for assets"""
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])
    
    # Get DNS records for the current project, only for monitored assets
    dns_records = DNSRecord.objects.filter(
        related_project=prj,
        related_asset__monitor=True
    ).select_related('related_asset').order_by('-last_checked')
    
    context['dns_records'] = dns_records
    context['total_records'] = dns_records.count()
    
    return render(request, 'findings/list_dns_records.html', context)

@login_required
def web_endpoints(request):
    """View web endpoints for assets"""
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])
    
    # Get endpoints for the current project, only for monitored assets
    endpoints = Endpoint.objects.filter(
        asset__related_project=prj,
        asset__monitor=True
    ).select_related('asset').order_by('-date')
    
    context['endpoints'] = endpoints
    context['total_endpoints'] = endpoints.count()
    
    return render(request, 'findings/list_web_endpoints.html', context)
