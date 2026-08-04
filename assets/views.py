from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.conf import settings
from django.utils.html import escape
import uuid as imported_uuid
from assets.models import Asset
from project.models import Project
from findings.models import DNSRecord, Endpoint, Screenshot
from jobs.utils import run_job
from assets.utils import export_assets_csv, upload_domains_from_file, ignore_asset
from assets.forms import AddSuggestionForm, AddAssetForm
import json
import threading

@login_required
def suggestions(request):
    """view all new and open suggestions
    """
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id'], 'suggestionform': AddSuggestionForm()}
    prj = Project.objects.get(id=request.session['current_project']['prj_id'])
    context['all_count'] = prj.asset_set.filter(ignore=False).count()
    context['secondleveldomain_count'] = prj.asset_set.filter(type='domain', subtype='domain', ignore=False).count()
    context['starreddomain_count'] = prj.asset_set.filter(type='starred_domain', ignore=False).count()
    context['ip_count'] = prj.asset_set.filter(type='ip', ignore=False).count()
    context['activetab'] = 'domain'
    return render(request, 'assets/list_suggestions.html', context)


@login_required
def manual_add_suggestion(request):
    """Manually add a suggestion with XSS prevention"""
    if not request.user.has_perm('assets.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        form = AddSuggestionForm(request.POST)
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

            # Generate UUID and save the record
            record.uuid = str(imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, f"{record.value}:{project_id}"))
            print(record.uuid)
            record.creation_time = timezone.now()
            
            # Ensure redirects_to is explicitly None to avoid foreign key issues
            record.redirects_to = None
            
            # Use force_insert to avoid potential update conflicts
            record.save(force_insert=True)

            messages.info(request, "Suggestion successfully added")
        else:
            # Print form errors to the console for debugging
            print(form.errors)
            messages.error(request, "Suggestion failed: %s" % form.errors.as_json(escape_html=False))
    return redirect(reverse('assets:suggestions'))


@login_required
def ignored_suggestions(request):
    """view all ignored suggestions
    """
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    context = {'projectid': request.session['current_project']['prj_id']}
    return render(request, 'assets/list_ignored_suggestions.html', context)

@login_required
def delete_suggestion(request, uuid):
    """remove a suggestion
    """
    if not request.user.has_perm('assets.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external').delete()
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('assets:suggestions'))
    return redirect(reverse('assets:suggestions'))

@login_required
def delete_suggestion_ignored(request, uuid):
    """remove a suggestion from ignored view
    """
    if not request.user.has_perm('assets.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external').delete()
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('assets:ignored_suggestions'))
    return redirect(reverse('assets:ignored_suggestions'))

@login_required
def monitor_suggestion(request, uuid):
    """move a suggestion to the monitored asset list
    """
    if not request.user.has_perm('assets.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external')
        if s_obj.type in ['certificate', 'domain']:
            s_obj.monitor = True
            s_obj.save()
            messages.info(request, 'Added %s to the monitoring' % s_obj.value)
            return redirect(reverse('assets:suggestions'))
        else:
            messages.error(request, 'Unsupported finding type: %s' % s_obj.type)
            return redirect(reverse('assets:suggestions'))
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('assets:suggestions'))

@login_required
def ignore_suggestion(request, uuid):
    """move suggestion to the ignore list
    """
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external')
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('assets:suggestions'))
    s_obj.ignore = True
    s_obj.save()
    return redirect(reverse('assets:suggestions'))

@login_required
def reactivate_suggestion(request, uuid):
    """reactivate an ignored suggestion
    """
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external')
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('assets:ignored_suggestions'))
    s_obj.ignore = False
    s_obj.save()
    return redirect(reverse('assets:ignored_suggestions'))

@login_required
def delete_all_suggestions(request):
    """delete all suggestions in given project
    """
    if not request.user.has_perm('assets.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('assets:suggestions'))
    # delete all suggestions (external-scope assets)
    prj_obj.asset_set.filter(scope='external').delete()
    return redirect(reverse('assets:suggestions'))

@login_required
def upload_suggestions(request):
    if not request.user.has_perm('assets.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
        
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('assets:suggestions'))
    
    return upload_domains_from_file(request, prj_obj, 'suggestions:suggestions')

@login_required
def scan_suggestions(request):
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        context = {'projectid': request.session['current_project']['prj_id']}
        project_id = context['projectid']

        # Fetch selected UUIDs from POST data (if any)
        selected_uuids = request.POST.getlist('uuid[]')

        def scan_redirect():
            try:
                command = 'get_domain_redirect'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running get_domain_redirect: {e}")

        def scan_dns_records():
            try:
                command = 'get_dns_records'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running get_dns_records: {e}")

        def monitor_all_unique_domains():
            s_objs = Asset.objects.filter(scope='external', related_project__id=project_id, type='domain').exclude(active=False).exclude(ignore=True)
            for s_obj in s_objs:
                s_obj.monitor = True
                s_obj.save()

        def subfinder_scan():
            try:
                command = 'scan_subfinder'
                args = f'--projectid {project_id}'
                if selected_uuids:
                    args += f' --uuids {",".join(selected_uuids)}'
                run_job(command, args, project_id, request.user)
            except Exception as e:
                print(f"Error running scan_subfinder: {e}")

        def chained_jobs():
            # Run jobs sequentially: subfinder -> scan for redirection -> monitor not redirecting
            # If scan for active status is selected, run it first AND last to ensure valid status of the domain assets
            if "scan_dns_records" in request.POST:
                scan_dns_records()
            if "subfinder_scan" in request.POST:
                subfinder_scan()
            if "scan_for_redirection" in request.POST:
                scan_redirect()
            if "scan_dns_records" in request.POST:
                scan_dns_records()
            if "monitor_not_redirecting" in request.POST:
                monitor_all_unique_domains()
        thread = threading.Thread(target=chained_jobs)
        thread.start()
        messages.info(request, 'Selected actions have been triggered in the background. (check jobs for scans)')

    return redirect(reverse('assets:suggestions'))

@login_required
def export_suggestions_csv(request):
    """Export all suggestions for the current project as a CSV file for download."""
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    project_id = request.session['current_project']['prj_id']

    return export_assets_csv(project_id, monitored_only=False, scope='external')


#### Monitored asset inventory ####
@login_required
def assets(request):
    # Check if the user has the "view_asset" permission
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])

    # Add form for manual asset addition
    context['assetform'] = AddAssetForm()
    return render(request, 'assets/list_assets.html', context)

@login_required
def move_asset(request, uuid):
    """disable monitoring for asset (equivalent to moving back to suggestions)
    """
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('assets:assets'))
    # disable monitoring
    a_obj.monitor = False
    a_obj.save()
    messages.info(request, f'Disabled monitoring for Asset: {a_obj.value}')
    return redirect(reverse('assets:assets'))

@login_required
def move_all_assets(request):
    """disable monitoring for all assets (equivalent to moving back to suggestions)
    """
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('assets:assets'))

    def move_all_assets_task(prj_obj):
        # disable monitoring for all assets
        a_objs = prj_obj.asset_set.filter(monitor=True)
        for a_obj in a_objs:
            a_obj.monitor = False
            a_obj.save()

    # Start processing in a background thread
    thread = threading.Thread(target=move_all_assets_task, args=(prj_obj,))
    thread.start()
    messages.success(request, "All monitored assets are being disabled in the background. Please refresh the page after a while to see the results.")

    return redirect(reverse('assets:assets'))

@login_required
def ignore_asset_glyphicon(request, uuid):
    """move asset to ignore list
    """
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    prj = Project.objects.get(id=context['projectid'])

    try:
        ignore_asset(uuid, prj)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)

    return redirect(reverse('assets:assets'))

@login_required
def delete_asset(request, uuid):
    """delete asset completely
    """
    if not request.user.has_perm('assets.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Exception as error:
        messages.error(request, 'Unknown: %s' % error)
        return redirect(reverse('assets:assets'))
    # delete the asset completely
    asset_value = a_obj.value
    a_obj.delete()
    messages.info(request, f'Deleted Asset: {asset_value}')
    return redirect(reverse('assets:assets'))

@login_required
def activate_asset(request, uuid):
    """move asset from ignore list back to active asset list
    """
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('assets:assets'))
    a_obj.monitor = True
    a_obj.save()
    return redirect(reverse('assets:assets'))

@login_required
def activate_all_assets(request):
    """Move all ignored assets back to active monitoring"""
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        # Get the current project
        prj_obj = Project.objects.get(id=context['projectid'])
    except Project.DoesNotExist:
        messages.error(request, 'Unknown Project')
        return redirect(reverse('assets:assets'))

    # Update all ignored assets for the project to set monitor=True
    prj_obj.asset_set.filter(monitor=False).update(monitor=True)

    messages.info(request, 'All ignored assets have been reactivated.')
    return redirect(reverse('assets:assets'))

@login_required
def view_asset(request, uuid):
    """view asset details
    """
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        a_obj = Asset.objects.get(uuid=uuid)
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Asset: %s' % uuid)
        return redirect(reverse('assets:assets'))
    dns_records = []
    if a_obj.type == 'domain':
        dns_records = DNSRecord.objects.filter(related_asset=a_obj).order_by('record_type', 'record_value')

    endpoints_all = Endpoint.objects.filter(asset=a_obj).order_by('-date')
    endpoints_total = endpoints_all.count()
    endpoints = list(endpoints_all[:20])
    endpoints_remaining = list(endpoints_all[20:])

    registrant_info_json = ''
    if a_obj.registrant_info:
        registrant_info_json = json.dumps(a_obj.registrant_info, indent=2)

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
        'registrant_info_json': registrant_info_json,
    }
    return render(request, 'assets/view_asset.html', context)

@login_required
def export_monitored_assets_csv(request):
    """Export all monitored assets for the current project as a CSV file for download."""
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return HttpResponseForbidden("No project selected.")

    return export_assets_csv(project_id, monitored_only=True, scope='external')

@login_required
def manual_add_asset(request):
    """Manually add an asset with XSS prevention"""
    if not request.user.has_perm('assets.add_asset'):
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
            record.creation_time = timezone.now()

            # Ensure redirects_to is explicitly None to avoid foreign key issues
            record.redirects_to = None

            # Use force_insert to avoid potential update conflicts
            record.save(force_insert=True)

            messages.info(request, "Asset successfully added")
        else:
            messages.error(request, "Asset failed: %s" % form.errors.as_json(escape_html=False))
    return redirect(reverse('assets:assets'))

@login_required
def upload_assets(request):
    if not request.user.has_perm('assets.add_asset'):
        return HttpResponseForbidden("You do not have permission.")

    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('assets:assets'))

    return upload_domains_from_file(request, prj_obj, 'assets:assets', monitor_new=True)
