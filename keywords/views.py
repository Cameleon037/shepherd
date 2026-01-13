# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST
import json

from project.models import Project, Keyword, Asset
from keywords.forms import AddKeywordForm
from django.core.management import call_command
import threading
from django.utils.html import escape

from jobs.utils import run_job

@login_required
def keywords(request):
    if not request.user.has_perm('project.view_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session['current_project']['prj_id']
    add_keyword_form = AddKeywordForm()
    
    descriptions = (
        Asset.objects.filter(related_project_id=project_id)
        .exclude(description__isnull=True)
        .exclude(description__exact="")
        .filter(description__icontains="registrant")
        .values_list('description', flat=True)
        .distinct()
    )
    context = {
        'projectid': project_id,
        'addkeywordform': add_keyword_form,
        'descriptions': descriptions
    }
    return render(request, 'keywords/list_keywords.html', context)

@login_required
def toggle_keyword(request, keywordid):
    if not request.user.has_perm('project.change_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        kw_obj = Keyword.objects.get(id=keywordid)
    except Keyword.DoesNotExist:
        kw_obj = None
    if kw_obj is not None:
        kw_obj.enabled = not kw_obj.enabled
        kw_obj.save()
    return redirect(reverse('keywords:keywords'))

@login_required
def delete_keyword(request, keywordid):
    if not request.user.has_perm('project.delete_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        kw_obj = Keyword.objects.get(id=keywordid).delete()
    except Keyword.DoesNotExist:
        return redirect(reverse('keywords:keywords'))
    return redirect(reverse('keywords:keywords'))

@login_required
def add_keyword(request):
    if not request.user.has_perm('project.add_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    prjid = request.session['current_project']['prj_id']
    if request.method == 'POST':
        form = AddKeywordForm(request.POST)
        if form.is_valid():
            try:
                prj_obj = Project.objects.get(id=prjid)
            except Exception as error:
                messages.error(request, "Project not found!")
                return redirect(reverse('keywords:keywords'))
            data = {
                'keyword': escape(form.cleaned_data['keyword']),
                'ktype': form.cleaned_data['ktype'],
                'description': escape(form.cleaned_data['description']),
                'related_project': prj_obj
            }
            Keyword.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
    return redirect(reverse('keywords:keywords'))

@login_required
def scan_keywords(request):
    if not request.user.has_perm('project.add_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        context = {'projectid': request.session['current_project']['prj_id']}
        
        if "crtsh" in request.POST:
            messages.info(request, 'CRTSH scan against monitored keywords has been triggered in the background.')

            try:
                # Get the project ID from the session
                projectid = context['projectid']

                # Define a function to run the command in a separate thread
                def run_command():
                    try:
                        command = 'import_crtsh'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running import_crtsh: {e}")

                # Start the thread
                thread = threading.Thread(target=run_command)
                thread.start()

            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "domaintools" in request.POST:
            messages.info(request, 'DomainTools scan against monitored keywords has been triggered in the background.')

            try:
                # Get the project ID from the session
                projectid = context['projectid']

                # Define a function to run the command in a separate thread
                def run_command():
                    try:
                        command = 'import_domaintools'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running import_domaintools: {e}")

                # Start the thread
                thread = threading.Thread(target=run_command)
                thread.start()

            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "shodan" in request.POST:
            messages.info(request, 'Shodan scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'import_shodan'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running import_shodan: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "porch-pirate" in request.POST:
            messages.info(request, 'Porch-pirate scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_porch-pirate'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_porch-pirate: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "swaggerhub" in request.POST:
            messages.info(request, 'SwaggerHub scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_swaggerhub'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_swaggerhub: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')

        if "ai_scribd" in request.POST:
            messages.info(request, 'AI powered Scribd scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_ai_scribd'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_ai_scribd: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')


    return redirect(reverse('keywords:keywords'))


@login_required
@require_POST
def bulk_update_keywords(request):
    """Bulk update keywords - add, update, or delete"""
    if not request.user.has_perm('project.add_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return JsonResponse({'success': False, 'message': 'No project selected.'}, status=400)

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON payload.'}, status=400)

    keywords_data = payload.get('keywords', [])
    
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Project not found.'}, status=400)

    # Get existing keyword IDs for this project
    existing_ids = set(
        Keyword.objects.filter(related_project=project).values_list('id', flat=True)
    )
    
    # Track which IDs we're keeping
    submitted_ids = set()
    
    for kw_data in keywords_data:
        kw_id = kw_data.get('id')
        keyword_value = escape(kw_data.get('keyword', '').strip())
        ktype = kw_data.get('ktype', 'registrant_org')
        description = escape(kw_data.get('description', '').strip())
        enabled = kw_data.get('enabled', True)
        
        if not keyword_value:
            continue
        
        if kw_id:
            # Update existing keyword
            submitted_ids.add(kw_id)
            try:
                kw = Keyword.objects.get(id=kw_id, related_project=project)
                kw.keyword = keyword_value
                kw.ktype = ktype
                kw.description = description
                kw.enabled = enabled
                kw.save()
            except Keyword.DoesNotExist:
                # ID doesn't exist, create new
                Keyword.objects.create(
                    related_project=project,
                    keyword=keyword_value,
                    ktype=ktype,
                    description=description,
                    enabled=enabled
                )
        else:
            # Create new keyword
            Keyword.objects.create(
                related_project=project,
                keyword=keyword_value,
                ktype=ktype,
                description=description,
                enabled=enabled
            )
    
    # Delete keywords that were removed (IDs in existing but not in submitted)
    ids_to_delete = existing_ids - submitted_ids
    if ids_to_delete:
        Keyword.objects.filter(id__in=ids_to_delete, related_project=project).delete()
    
    return JsonResponse({
        'success': True,
        'message': 'Keywords updated successfully.'
    })


@login_required
def discovery_control_center(request):
    """Discovery Control Center - manage keyword-based discovery scans"""
    if not request.user.has_perm('project.view_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session.get('current_project', {}).get('prj_id', None)
    keywords = []
    if project_id:
        keywords = Keyword.objects.filter(
            related_project_id=project_id,
            enabled=True
        ).order_by('keyword')
    
    context = {
        'projectid': project_id,
        'keywords': keywords,
    }
    return render(request, 'keywords/discovery_control_center.html', context)


@login_required
@require_POST
def discovery_control_center_launch(request):
    """Launch discovery scans from Discovery Control Center"""
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        return JsonResponse({'success': False, 'message': 'No project selected.'}, status=400)

    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'message': 'Invalid JSON payload.'}, status=400)

    keyword_ids = payload.get('keywords', [])  # Empty means all
    scans = payload.get('scans', {})
    auto_monitor = payload.get('auto_monitor', False)
    post_actions = payload.get('post_actions', {})

    # Build keyword filter args
    keyword_args = ''
    if keyword_ids:
        keyword_args = f' --keyword-ids {",".join(str(k) for k in keyword_ids)}'

    threads = []
    triggered_messages = []
    user = request.user  # Capture user for use in threads

    def launch(command, extra=''):
        args = f'--projectid {project_id}{extra}'
        run_job(command, args, project_id, user)

    if scans.get('scan_crtsh'):
        threads.append(threading.Thread(target=lambda: launch('import_crtsh', keyword_args)))
        triggered_messages.append('Crt.sh scan triggered.')

    if scans.get('scan_domaintools'):
        threads.append(threading.Thread(target=lambda: launch('import_domaintools', keyword_args)))
        triggered_messages.append('DomainTools scan triggered.')

    if scans.get('scan_shodan'):
        threads.append(threading.Thread(target=lambda: launch('import_shodan', keyword_args)))
        triggered_messages.append('Shodan scan triggered.')

    if scans.get('scan_servicenow'):
        threads.append(threading.Thread(target=lambda: launch('import_snow_cmdb')))
        triggered_messages.append('ServiceNow CMDB import triggered.')

    if scans.get('scan_porch_pirate'):
        threads.append(threading.Thread(target=lambda: launch('scan_porch-pirate', keyword_args)))
        triggered_messages.append('Porch-pirate scan triggered.')

    if scans.get('scan_swaggerhub'):
        threads.append(threading.Thread(target=lambda: launch('scan_swaggerhub', keyword_args)))
        triggered_messages.append('SwaggerHub scan triggered.')

    if scans.get('scan_ai_scribd'):
        threads.append(threading.Thread(target=lambda: launch('scan_ai_scribd', keyword_args)))
        triggered_messages.append('ShepherdAI + Scribd scan triggered.')

    # Subfinder runs after discovery scans (step 3)
    run_subfinder = scans.get('scan_subfinder', False)

    # Check if any post-discovery actions are selected (step 4)
    run_dns_records = post_actions.get('dns_records', False)
    run_domain_redirect = post_actions.get('domain_redirect', False)
    has_post_actions = run_dns_records or run_domain_redirect or auto_monitor

    # Validate that at least something is selected
    if not threads and not run_subfinder and not has_post_actions:
        return JsonResponse({'success': False, 'message': 'Select at least one scan or action.'}, status=400)

    # Start all discovery scan threads in parallel
    for thread in threads:
        thread.start()

    # If subfinder or post-actions are selected, run them in sequence after discovery
    if run_subfinder or has_post_actions:
        def run_sequential_actions():
            # Wait for all discovery scan threads to complete
            for t in threads:
                t.join()
            
            # Step 3: Run Subfinder (against starred domains)
            if run_subfinder:
                launch('scan_subfinder')
            
            # Step 4: Run post-discovery actions
            # Run Domain Redirect scan first
            if run_domain_redirect:
                launch('get_domain_redirect')
            
            # Run DNS Records scan
            if run_dns_records:
                launch('get_dns_records')
            
            # Update assets: set monitor=True for domains that are not inactive and not ignored
            if auto_monitor:
                Asset.objects.filter(
                    related_project_id=project_id,
                    type='domain'
                ).exclude(active=False).exclude(ignore=True).update(monitor=True)
        
        post_thread = threading.Thread(target=run_sequential_actions)
        post_thread.start()
        
        if run_subfinder:
            triggered_messages.append('Subfinder will run after discovery (on starred domains).')
        if run_domain_redirect:
            triggered_messages.append('Domain Redirect scan will run after Subfinder.')
        if run_dns_records:
            triggered_messages.append('DNS Records scan will run after Domain Redirect.')
        if auto_monitor:
            triggered_messages.append('Auto-monitor will be applied after all scans complete.')

    return JsonResponse({
        'success': True,
        'messages': triggered_messages,
    })
