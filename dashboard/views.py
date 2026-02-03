from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.http import HttpResponseForbidden
from django.shortcuts import render

from project.models import Asset, Project, Keyword
from findings.models import Finding, Port, Screenshot


@login_required
def dashboard(request):
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    project_id = request.session.get('current_project', {}).get('prj_id')
    context = {
        'project_name': None,
        'has_project': False,
        'projectid': project_id,
    }

    if not project_id:
        return render(request, 'dashboard/dashboard.html', context)

    try:
        prj = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return render(request, 'dashboard/dashboard.html', context)

    context['project_name'] = prj.projectname
    context['has_project'] = True

    # Asset counts by type
    assets = Asset.objects.filter(related_project_id=project_id)
    context['num_assets'] = assets.count()
    context['num_domains'] = assets.filter(type='domain').count()
    context['num_ips'] = assets.filter(type='ip').count()
    context['num_ignored_assets'] = assets.filter(ignore=True).count()
    context['num_monitored'] = assets.filter(monitor=True).count()

    # Keywords count
    context['num_keywords'] = Keyword.objects.filter(related_project_id=project_id, enabled=True).count()

    # Findings (via asset's related_project)
    findings = Finding.objects.filter(domain__related_project_id=project_id).exclude(ignore=True)
    context['num_findings'] = findings.count()
    context['findings_by_severity'] = list(
        findings.values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    # Order severity for display (critical first, then high, medium, low, info, unknown)
    severity_order = ['critical', 'high', 'medium', 'low', 'info', '']
    def severity_sort_key(x):
        s = (x.get('severity') or '').lower()
        try:
            return severity_order.index(s)
        except ValueError:
            return 99
    context['findings_by_severity'] = sorted(
        context['findings_by_severity'],
        key=severity_sort_key,
    )

    # Recent findings (last 10)
    context['recent_findings'] = (
        findings.select_related('domain')
        .order_by('-first_seen')[:10]
    )

    # Ports (open ports on assets)
    context['num_ports'] = Port.objects.filter(domain__related_project_id=project_id).count()

    # Screenshots count
    context['num_screenshots'] = Screenshot.objects.filter(domain__related_project_id=project_id).count()

    # Top finding sources (simple count)
    context['findings_by_source'] = list(
        findings.values('source')
        .annotate(count=Count('id'))
        .order_by('-count')[:8]
    )

    # Most critical findings (prioritize critical/high severity, then by most recent)
    severity_order_map = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, '': 99}
    critical_findings = list(
        findings.select_related('domain')
        .exclude(severity__isnull=True)
        .exclude(severity='')
        .exclude(domain__isnull=True)  # Only include findings with assets
        .order_by('-first_seen')[:50]  # Get more to sort properly
    )
    # Sort by severity priority, then by first_seen
    critical_findings.sort(
        key=lambda x: (
            severity_order_map.get((x.severity or '').lower(), 99),
            -x.first_seen.timestamp() if x.first_seen else 0
        )
    )
    context['most_critical_findings'] = critical_findings[:10]  # Top 10

    # Most vulnerable assets (assets with most findings)
    context['most_vulnerable_assets'] = list(
        assets.annotate(finding_count=Count('finding', filter=Q(finding__ignore=False)))
        .filter(finding_count__gt=0)
        .order_by('-finding_count')[:10]
        .values('uuid', 'value', 'finding_count')
    )

    # Findings by source with severity breakdown (for stacked bar chart)
    sources_data = {}
    findings_with_source = findings.exclude(source__isnull=True).exclude(source='')
    for finding in findings_with_source:
        source = finding.source
        severity = (finding.severity or '').lower()
        if severity not in ['critical', 'high', 'medium', 'low', 'info']:
            severity = 'unknown'
        
        if source not in sources_data:
            sources_data[source] = {
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0, 'total': 0
            }
        sources_data[source][severity] += 1
        sources_data[source]['total'] += 1
    
    # Convert to list and sort by total descending
    context['findings_by_source_stacked'] = sorted(
        [
            {'source': k, **v}
            for k, v in sources_data.items()
        ],
        key=lambda x: x['total'],
        reverse=True
    )[:10]  # Top 10 sources

    return render(request, 'dashboard/dashboard.html', context)
