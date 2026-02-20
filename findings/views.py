import tld
import uuid as imported_uuid
from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import make_aware
from django.utils.html import escape
from django.http import HttpResponseForbidden, JsonResponse, StreamingHttpResponse
from django.db.models import Q
from django.views.decorators.http import require_POST
from project.models import Project, Asset, DNSRecord
from findings.models import Finding, Port, Screenshot, Endpoint
from findings.utils import asset_get_or_create, asset_finding_get_or_create, ignore_asset, ignore_finding
from suggestions.utils import export_assets_csv, upload_domains_from_file
from findings.forms import AddAssetForm
import threading
from jobs.utils import run_job
import csv
import json
import tempfile, os
from project.scan_utils import write_uuids_file


def _filter_assets_for_project(project_id, filters):
    queryset = Asset.objects.filter(related_project_id=project_id, monitor=True)

    asset_type = (filters.get('type') or '').strip()
    if asset_type:
        queryset = queryset.filter(type=asset_type)

    scope = (filters.get('scope') or '').strip()
    if scope:
        queryset = queryset.filter(scope__iexact=scope)

    sources = filters.get('sources') or []
    if isinstance(sources, str):
        sources = [sources]
    sources = [src.strip() for src in sources if src and src.strip()]
    if sources:
        query = Q()
        for src in sources:
            query |= Q(source__icontains=src)
        queryset = queryset.filter(query)

    name = (filters.get('name') or '').strip()
    if name:
        queryset = queryset.filter(value__icontains=name)

    return queryset


def _run_scan_jobs(project_id, user, selected_uuids, scan_new_assets, scans):
    selected_uuids = [str(uuid) for uuid in (selected_uuids or [])]
    threads = []
    triggered_messages = []

    def add_message(text):
        if text:
            triggered_messages.append(text)

    def launch(command, extra=""):
        args = f'--projectid {project_id}{extra}'
        if selected_uuids:
            uuids_file = write_uuids_file(selected_uuids)
            args += f' --uuids-file {uuids_file}'
        if scan_new_assets:
            args += ' --new-assets'
        run_job(command, args, project_id, user)

    def scan_nmap():
        launch('scan_nmap')

    def scan_httpx():
        launch('scan_httpx')

    def scan_playwright():
        launch('scan_playwright')

    def scan_katana():
        launch('scan_katana')

    def scan_shepherdai():
        launch('scan_shepherdai')

    def scan_nuclei():
        launch('scan_nuclei')

    def scan_nuclei_nt():
        launch('scan_nuclei', ' --nt')

    def scan_dns_records():
        launch('get_dns_records')

    def scan_domain_redirect():
        launch('get_domain_redirect')

    scan_dns_records_flag = scans.get('scan_dns_records')
    scan_domain_redirect_flag = scans.get('scan_domain_redirect')
    scan_nmap_flag = scans.get('scan_nmap')
    scan_httpx_flag = scans.get('scan_httpx')
    scan_playwright_flag = scans.get('scan_playwright')
    scan_katana_flag = scans.get('scan_katana')
    scan_shepherdai_flag = scans.get('scan_shepherdai')
    scan_nuclei_flag = scans.get('scan_nuclei')
    scan_nuclei_new_flag = scans.get('scan_nuclei_new_templates')

    # Check if we need to chain Nmap -> Screenshot (HTTPX or Playwright) and/or Katana
    screenshot_selected = scan_httpx_flag or scan_playwright_flag
    nmap_then_screenshot = scan_nmap_flag and screenshot_selected
    nmap_then_katana = scan_nmap_flag and scan_katana_flag
    nmap_chained = nmap_then_screenshot or nmap_then_katana

    # Primary threads: all scans except Shepherd AI (which runs last)
    primary_threads = []

    if scan_dns_records_flag:
        primary_threads.append(threading.Thread(target=scan_dns_records))
        add_message('DNS Records scan has been triggered in the background. (check jobs)')

    if scan_domain_redirect_flag:
        primary_threads.append(threading.Thread(target=scan_domain_redirect))
        add_message('Domain Redirect scan has been triggered in the background. (check jobs)')

    if nmap_chained:
        # Create a chained thread: Nmap runs first, then screenshot engine(s) and/or Katana after completion
        def nmap_then_dependent_scans():
            scan_nmap()  # This blocks until Nmap job completes
            if scan_httpx_flag:
                scan_httpx()
            if scan_playwright_flag:
                scan_playwright()
            if scan_katana_flag:
                scan_katana()
        
        primary_threads.append(threading.Thread(target=nmap_then_dependent_scans))
        add_message('Nmap scan has been triggered in the background. (check jobs)')
        if scan_httpx_flag:
            add_message('Httpx scan will start after Nmap completes. (check jobs)')
        if scan_playwright_flag:
            add_message('Playwright scan will start after Nmap completes. (check jobs)')
        if scan_katana_flag:
            add_message('Katana scan will start after Nmap completes. (check jobs)')
    else:
        # No dependency - run independently
        if scan_nmap_flag:
            primary_threads.append(threading.Thread(target=scan_nmap))
            add_message('Nmap scan has been triggered in the background. (check jobs)')

        if scan_httpx_flag:
            primary_threads.append(threading.Thread(target=scan_httpx))
            add_message('Httpx scan has been triggered in the background. (check jobs)')

        if scan_playwright_flag:
            primary_threads.append(threading.Thread(target=scan_playwright))
            add_message('Playwright scan has been triggered in the background. (check jobs)')

        if scan_katana_flag:
            primary_threads.append(threading.Thread(target=scan_katana))
            add_message('Katana scan has been triggered in the background. (check jobs)')

    if scan_nuclei_flag:
        primary_threads.append(threading.Thread(target=scan_nuclei))
        add_message('Nuclei scan has been triggered in the background. (check jobs)')

    if scan_nuclei_new_flag:
        primary_threads.append(threading.Thread(target=scan_nuclei_nt))
        add_message('Nuclei scan for new templates has been triggered in the background. (check jobs)')

    # Handle Shepherd AI: it should run after all other scans complete
    if scan_shepherdai_flag:
        if primary_threads:
            # Shepherd AI runs after all primary scans complete
            def run_shepherdai_after_all():
                # Start all primary threads
                for t in primary_threads:
                    t.start()
                # Wait for all primary threads to complete
                for t in primary_threads:
                    t.join()
                # Now run Shepherd AI
                scan_shepherdai()
            
            threads.append(threading.Thread(target=run_shepherdai_after_all))
            add_message('Shepherd AI will run after all other scans complete. (check jobs)')
        else:
            # No other scans selected, just run Shepherd AI directly
            threads.append(threading.Thread(target=scan_shepherdai))
            add_message('Shepherd AI scan has been triggered in the background. (check jobs)')
    else:
        # No Shepherd AI - just add all primary threads to be started
        threads.extend(primary_threads)

    for thread in threads:
        thread.start()

    return triggered_messages


#### Asset stuffs
@login_required
def assets(request):
    # Check if the user has the "view_project" permission or is in the read-only users
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])
    
    # Add form for manual asset addition
    context['assetform'] = AddAssetForm()

    # check for POST request
    if request.method == 'POST':
        if not request.user.has_perm('project.change_asset'):
            return HttpResponseForbidden("You do not have permission.")
        # determine action
        if "btnignore" in request.POST:
            action = "ignore"
        elif "btnmove" in request.POST:
            action = "move"
        elif "btndelete" in request.POST:
            action = "delete"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:assets'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for uuid in id_lst:
            if action == "ignore":
                try:
                    ignore_asset(uuid, prj)
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % uuid)
                    continue # take next item
                messages.info(request, 'Ignored Asset: %s' % Asset.objects.get(uuid=uuid).value)
            elif action == "move":
                try:
                    a_obj = Asset.objects.get(uuid=uuid)
                    # disable monitoring (equivalent to moving back to suggestions)
                    a_obj.monitor = False
                    a_obj.save()
                except Exception as error:
                    messages.error(request, 'Unknown: %s' % error)
                    continue # take next item
                messages.info(request, 'Disabled monitoring for Asset: %s' % a_obj.value)
            elif action == "delete":
                try:
                    a_obj = Asset.objects.get(uuid=uuid)
                    domain_to_delete = a_obj.value
                    a_obj.delete()
                    messages.info(request, 'Deleted Asset: %s' % domain_to_delete)
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Asset: %s' % uuid)
                    continue  # take next item
        # redirect to asset list
        return redirect(reverse('findings:assets'))
    else:
        # anything that needs to be done for GET request?
        pass
    return render(request, 'findings/list_assets.html', context)

@login_required
def move_asset(request, uuid):
    """disable monitoring for asset (equivalent to moving back to suggestions)
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('findings:assets'))
    # disable monitoring
    a_obj.monitor = False
    a_obj.save()
    messages.info(request, f'Disabled monitoring for Asset: {a_obj.value}')
    return redirect(reverse('findings:assets'))

@login_required
def move_all_assets(request):
    """disable monitoring for all assets (equivalent to moving back to suggestions)
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('findings:assets'))

    def move_all_assets_task(prj_obj):
        # disable monitoring for all assets
        a_objs = prj_obj.asset_set.filter(monitor=True)
        for a_obj in a_objs:
            a_obj.monitor = False
            a_obj.save()

    # Start processing in a background thread
    thread = threading.Thread(target=move_all_assets_task, args=(prj_obj,))
    thread.start()
    messages.success(request, f"All monitored assets are being disabled in the background. Please refresh the page after a while to see the results.")

    return redirect(reverse('findings:assets'))

@login_required
def ignore_asset_glyphicon(request, uuid):
    """move asset to ignore list
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])
    
    try:
        ignore_asset(uuid, prj)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)

    return redirect(reverse('findings:assets'))

@login_required
def ignore_finding_glyphicon(request, findingid):
    """Toggle finding ignore status (AJAX endpoint)
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission to modify findings.")

    try:
        ignore_finding(findingid)
        return JsonResponse({'success': True, 'message': 'Ignore status toggled successfully.'})
    except Finding.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Unknown Finding: %s' % findingid}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def delete_asset(request, uuid):
    """delete asset completely
    """
    if not request.user.has_perm('project.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('findings:assets'))
    # delete the asset completely
    asset_value = a_obj.value
    a_obj.delete()
    messages.info(request, f'Deleted Asset: {asset_value}')
    return redirect(reverse('findings:assets'))

@login_required
def activate_asset(request, uuid):
    """move asset from ignore list back to active asset list
    """
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    a_obj.monitor = True
    a_obj.save()
    return redirect(reverse('findings:assets'))

@login_required
def activate_all_assets(request):
    """Move all ignored assets back to active monitoring"""
    if not request.user.has_perm('project.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        # Get the current project
        prj_obj = Project.objects.get(id=context['projectid'])
    except Project.DoesNotExist:
        messages.error(request, 'Unknown Project')
        return redirect(reverse('findings:ignored_assets'))

    # Update all ignored assets for the project to set monitor=True
    prj_obj.asset_set.filter(monitor=False).update(monitor=True)

    messages.info(request, 'All ignored assets have been reactivated.')
    return redirect(reverse('findings:assets'))

@login_required
def view_asset(request, uuid):
    """view asset details
    """
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('findings:assets'))
    dns_records = []
    if a_obj.type == 'domain':
        dns_records = DNSRecord.objects.filter(related_asset=a_obj).order_by('record_type', 'record_value')

    endpoints_all = Endpoint.objects.filter(asset=a_obj).order_by('-date')
    endpoints_total = endpoints_all.count()
    endpoints = list(endpoints_all[:20])
    endpoints_remaining = list(endpoints_all[20:])

    context = {
        'asset': a_obj,
        'ports': a_obj.port_set.all().order_by('port'),
        'screenshots': Screenshot.objects.filter(asset=a_obj).order_by('-date'),
        'findings': a_obj.finding_set.filter(ignore=False).order_by('-severity', '-scan_date', '-id'),
        'ignored_findings': a_obj.finding_set.filter(ignore=True).order_by('-severity', '-scan_date', '-id'),
        'dns_records': dns_records,
        'endpoints': endpoints,
        'endpoints_total': endpoints_total,
        'endpoints_remaining': endpoints_remaining,
    }
    return render(request, 'findings/view_asset.html', context)

### Nucleus stuffs
@login_required
def send_nucleus(request, findingid):
    """ send the details of the finding to Nucleus
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        f_obj = Finding.objects.get(id=findingid)
    except Finding.DoesNotExist:
        messages.error(request, 'Unknown Finding: %s' % findingid)
        return redirect(reverse('findings:assets'))

    # prepare header
    rheader = {'x-apikey': settings.NUCLEUS_KEY, 'Content-Type': 'application/json'}
    # asset = tld.get_tld(f_obj.asset.value, fix_protocol=True, as_object=True)
    asset_name, asset_id = asset_get_or_create(f_obj.asset.value, settings.NUCLEUS_URL, settings.NUCLEUS_PROJECT, rheader)
    # print(asset_name, asset_id)
    # add finding
    result, msg = asset_finding_get_or_create(asset_name, asset_id, f_obj, settings.NUCLEUS_URL, settings.NUCLEUS_PROJECT, rheader)
    # update reporting time
    f_obj.last_reported = timezone.now()
    f_obj.reported = True
    f_obj.save()

    # Return success response
    return JsonResponse({'success': True, 'message': 'Finding sent to Nucleus successfully.'})


### Nmap stuffs
@login_required
def nmap_results(request):
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    if request.method == 'POST':
        if 'btndelete' in request.POST:
            if not request.user.has_perm('findings.delete_port'):
                return HttpResponseForbidden("You do not have permission.")

            port_ids = request.POST.getlist('id[]')
            port_objs = Port.objects.filter(id__in=port_ids)
            for port_obj in port_objs:
                port_obj.delete()
            messages.info(request, 'Deleted selected ports')
        else:
            messages.error(request, 'Unknown action received!')
        print(request.POST)
    return render(request, 'findings/list_nmap_results.html', context)


### Scanners stuffs
@login_required
def recent_findings(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('projects:projects'))
    # count 
    # severity findings
    five_days = datetime.now() - timedelta(days=settings.RECENT_DAYS) # X days ago
    recent_active_domains = prj_obj.asset_set.all().filter(monitor=True, last_scan_time__gte=make_aware(five_days))
    context['num_info'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), asset__in=recent_active_domains, 
    severity='info').count()
    context['num_low'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), asset__in=recent_active_domains, 
    severity='low').count()
    context['num_medium'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), asset__in=recent_active_domains, 
    severity='medium').count()
    context['num_high'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), asset__in=recent_active_domains, 
    severity='high').count()
    context['num_critical'] = Finding.objects.filter(last_seen__gte=make_aware(five_days), asset__in=recent_active_domains, 
    severity='critical').count()
    context['past_days'] = settings.RECENT_DAYS
    context['activetab'] = 'critical'
    return render(request, 'findings/list_recent_findings.html', context)

@login_required
def all_findings(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}

    if request.method == 'POST':
        # determine action
        if "btndelete" in request.POST:
            if not request.user.has_perm('findings.delete_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "delete"
        elif "btnreport" in request.POST:
            if not request.user.has_perm('findings.change_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "report"
        elif "btnignore" in request.POST:
            if not request.user.has_perm('findings.change_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "ignore"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:all_findings'))
        # get IDs of items
        id_lst = request.POST.getlist('id[]')

        if action == "delete":
            for findingid in id_lst:
                try:
                    Finding.objects.get(id=findingid).delete()
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Selected findings deleted successfully.')

        if action == "report":
            for findingid in id_lst:
                try:
                    send_nucleus(request, findingid)
                except Finding.DoesNotExist:
                    messages.error(request, 'Failed reporting Finding: %s' % findingid)
                    continue  # take next item

        if action == "ignore":
            for findingid in id_lst:
                try:
                    ignore_finding(findingid)
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Ignore status toggled for selected findings.')

        return redirect(reverse('findings:all_findings'))
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
        return redirect(reverse('findings:assets'))
    a_obj.finding_set.filter(id=findingid).delete() 
    messages.info(request, 'finding deleted!')
    return redirect(reverse('findings:view_asset', args=(uuid,)))

@require_POST
@login_required
def scan_assets(request):
    """Store selected asset UUIDs in session and redirect to the control center."""
    if not request.user.has_perm('findings.add_finding'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON.'}, status=400)

    selected_uuids = payload.get('uuids', [])
    if not selected_uuids:
        return JsonResponse({'success': False, 'message': 'No assets selected.'}, status=400)

    request.session['scan_selected_uuids'] = [str(u) for u in selected_uuids]
    return JsonResponse({'success': True, 'redirect': reverse('findings:control_center')})

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
    if not request.user.has_perm('project.view_asset'):
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
def control_center_preview(request):
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return JsonResponse({'error': 'No project selected.'}, status=400)

    sources = request.GET.getlist('sources[]') or request.GET.getlist('sources')
    filters = {
        'type': request.GET.get('type'),
        'scope': request.GET.get('scope'),
        'sources': sources,
        'name': request.GET.get('name'),
    }
    queryset = _filter_assets_for_project(project_id, filters)
    new_assets_only = request.GET.get('new_assets_only')
    if new_assets_only:
        queryset = queryset.filter(last_scan_time__isnull=True)
    count = queryset.count()
    sample = list(
        queryset.values('uuid', 'value', 'type', 'scope', 'source')[:25]
    )
    return JsonResponse({'count': count, 'sample': sample})


@login_required
@require_POST
def control_center_launch(request):
    if not request.user.has_perm('findings.add_finding'):
        return HttpResponseForbidden("You do not have permission.")
    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return JsonResponse({'success': False, 'message': 'No project selected.'}, status=400)

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON payload.'}, status=400)

    filters = payload.get('filters', {})
    scans = payload.get('scans', {})
    asset_mode = payload.get('asset_mode', 'all')

    scan_new_assets = False
    if asset_mode == 'all':
        asset_ids = []
        asset_count_display = Asset.objects.filter(related_project_id=project_id, monitor=True).count()
    elif asset_mode == 'new':
        asset_ids = []
        scan_new_assets = True
        asset_count_display = Asset.objects.filter(
            related_project_id=project_id, monitor=True, last_scan_time__isnull=True
        ).count()
    elif asset_mode == 'selected':
        asset_ids = payload.get('selected_uuids', [])
        if not asset_ids:
            return JsonResponse({'success': False, 'message': 'No pre-selected assets.'}, status=400)
        asset_count_display = len(asset_ids)
    else:
        # "filter" mode: resolve UUIDs via filters
        queryset = _filter_assets_for_project(project_id, filters)
        asset_ids = list(queryset.values_list('uuid', flat=True))
        if not asset_ids:
            return JsonResponse({'success': False, 'message': 'No assets match the filters.'}, status=400)
        asset_count_display = len(asset_ids)

    scan_flags = {
        'scan_nmap': bool(scans.get('scan_nmap')),
        'scan_httpx': bool(scans.get('scan_httpx')),
        'scan_playwright': bool(scans.get('scan_playwright')),
        'scan_katana': bool(scans.get('scan_katana')),
        'scan_shepherdai': bool(scans.get('scan_shepherdai')),
        'scan_nuclei': bool(scans.get('scan_nuclei')),
        'scan_nuclei_new_templates': bool(scans.get('scan_nuclei_new_templates')),
    }

    if not any(scan_flags.values()):
        return JsonResponse({'success': False, 'message': 'Select at least one scanner.'}, status=400)

    triggered = _run_scan_jobs(project_id, request.user, asset_ids, scan_new_assets, scan_flags)
    return JsonResponse({
        'success': True,
        'asset_count': asset_count_display,
        'messages': triggered,
    })

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
def export_monitored_assets_csv(request):
    """Export all monitored assets for the current project as a CSV file for download."""
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return HttpResponseForbidden("No project selected.")
    
    return export_assets_csv(project_id, monitored_only=True, scope='external')

@login_required
def data_leaks(request):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}

    if request.method == 'POST':
        # determine action
        if "btndelete" in request.POST:
            if not request.user.has_perm('findings.delete_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "delete"
        elif "btnignore" in request.POST:
            if not request.user.has_perm('findings.change_finding'):
                return HttpResponseForbidden("You do not have permission.")
            action = "ignore"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('findings:data_leaks'))
        # get IDs of items
        id_lst = request.POST.getlist('id[]')

        if action == "delete":
            for findingid in id_lst:
                try:
                    Finding.objects.get(id=findingid).delete()
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Selected findings deleted successfully.')

        if action == "ignore":
            for findingid in id_lst:
                try:
                    ignore_finding(findingid)
                except Finding.DoesNotExist:
                    messages.error(request, 'Unknown Finding: %s' % findingid)
                    continue  # take next item
            messages.info(request, 'Ignore status toggled for selected findings.')

    return render(request, 'findings/list_data_leaks.html', context)


@login_required
def manual_add_asset(request):
    """Manually add an asset with XSS prevention"""
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        form = AddAssetForm(request.POST)
        if form.is_valid():
            record = form.save(commit=False)

            # Sanitize all fields to prevent XSS
            record.value = escape(record.value)
            record.description = escape(record.description) if record.description else None
            record.source = escape(record.source) if record.source else None
            record.link = escape(record.link) if record.link else None

            # Set related_project to currently selected project
            project_id = request.session['current_project']['prj_id']
            record.related_project_id = project_id

            # Set scope to external for assets created from suggestions
            record.scope = 'external'
            
            # Set monitor to True for assets (unlike suggestions which are False by default)
            record.monitor = True

            # Generate UUID and save the record
            record.uuid = str(imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, f"{record.value}:{project_id}"))
            print(record.uuid)
            record.creation_time = timezone.now()
            
            # Ensure redirects_to is explicitly None to avoid foreign key issues
            record.redirects_to = None
            
            # Use force_insert to avoid potential update conflicts
            record.save(force_insert=True)

            messages.info(request, "Asset successfully added")
        else:
            # Print form errors to the console for debugging
            print(form.errors)
            messages.error(request, "Asset failed: %s" % form.errors.as_json(escape_html=False))
    return redirect(reverse('findings:assets'))


@login_required
def upload_assets(request):
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
        
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('findings:assets'))
    
    return upload_domains_from_file(request, prj_obj, 'findings:assets', monitor_new=True)


@login_required
def dns_records(request):
    """View DNS records for assets"""
    if not request.user.has_perm('project.view_asset'):
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
    if not request.user.has_perm('project.view_asset'):
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


@login_required
@require_POST
def scan_burp_endpoints(request):
    """Trigger a Burp Suite scan against selected web endpoint URLs."""
    if not request.user.has_perm('findings.add_finding'):
        return JsonResponse({'success': False, 'message': 'Permission denied.'}, status=403)

    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return JsonResponse({'success': False, 'message': 'No project selected.'}, status=400)

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON payload.'}, status=400)

    urls = payload.get('urls', [])
    if not urls:
        return JsonResponse({'success': False, 'message': 'No URLs selected.'}, status=400)

    # Write URLs to a temp file to avoid OS argument length limits
    fd, urls_file = tempfile.mkstemp(prefix='burp_urls_', suffix='.json', dir='/tmp')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(urls, f)
    except Exception:
        os.close(fd)
        return JsonResponse({'success': False, 'message': 'Failed to prepare scan.'}, status=500)

    args = f'--wait --urls-file {urls_file}'

    # Launch the job in a background thread so the request returns immediately
    thread = threading.Thread(
        target=run_job,
        args=('scan_burp', args, project_id, request.user),
    )
    thread.start()

    return JsonResponse({
        'success': True,
        'message': f'Burp Suite scan triggered for {len(urls)} URL(s). Check Jobs for progress.',
    })
