from django.contrib.auth.decorators import login_required
from django.db.models import Case, Count, IntegerField, Q, Value, When
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
    # Exclude findings that are ignored OR findings related to ignored domains
    findings = Finding.objects.filter(asset__related_project_id=project_id).exclude(ignore=True).exclude(asset__ignore=True)
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
        findings.select_related('asset')
        .order_by('-first_seen')[:10]
    )

    # Ports (open ports on assets)
    context['num_ports'] = Port.objects.filter(asset__related_project_id=project_id).count()

    # Screenshots count
    context['num_screenshots'] = Screenshot.objects.filter(asset__related_project_id=project_id).count()

    # Top finding sources (simple count)
    context['findings_by_source'] = list(
        findings.values('source')
        .annotate(count=Count('id'))
        .order_by('-count')[:8]
    )

    # Most critical findings: order by severity (critical first) then by most recent
    severity_order_expr = Case(
        When(severity__iexact='critical', then=Value(0)),
        When(severity__iexact='high', then=Value(1)),
        When(severity__iexact='medium', then=Value(2)),
        When(severity__iexact='low', then=Value(3)),
        When(severity__iexact='info', then=Value(4)),
        default=Value(99),
        output_field=IntegerField(),
    )
    context['most_critical_findings'] = list(
        findings.select_related('asset')
        .exclude(severity__isnull=True)
        .exclude(severity='')
        .exclude(asset__isnull=True)
        .order_by(severity_order_expr, '-first_seen')[:10]
    )

    # Most vulnerable assets (assets with most findings; exclude ignored assets)
    # Count only non-ignored findings from non-ignored domains
    context['most_vulnerable_assets'] = list(
        assets.filter(ignore=False)
        .annotate(finding_count=Count('finding', filter=Q(finding__ignore=False) & Q(finding__asset__ignore=False)))
        .filter(finding_count__gt=0)
        .order_by('-finding_count')[:10]
        .values('uuid', 'value', 'finding_count')
    )

    # Findings overview: single bar showing findings by severity
    findings_overview = {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0, 'total': 0
    }
    for finding in findings:
        severity = (finding.severity or '').lower()
        if severity not in ['critical', 'high', 'medium', 'low', 'info']:
            severity = 'unknown'
        findings_overview[severity] += 1
        findings_overview['total'] += 1
    context['findings_overview'] = findings_overview

    return render(request, 'dashboard/dashboard.html', context)
