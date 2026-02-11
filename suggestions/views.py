from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.conf import settings
from django.utils.html import escape
import uuid as imported_uuid
from project.models import Asset, Project
from jobs.utils import run_job
from suggestions.utils import export_assets_csv, upload_domains_from_file
from suggestions.forms import AddSuggestionForm
import json
import threading

@login_required
def suggestions(request):
    """view all new and open suggestions
    """
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id'], 'suggestionform': AddSuggestionForm()}
    # check for POST request
    if request.method == 'POST':
        # determine action
        if "btnmonitor" in request.POST:
            if not request.user.has_perm('project.change_asset'):
                return HttpResponseForbidden("You do not have permission.")
            action = "monitor"
        elif "btnignore" in request.POST:
            if not request.user.has_perm('project.change_asset'):
                return HttpResponseForbidden("You do not have permission.")
            action = "ignore"
        elif "btndelete" in request.POST:
            if not request.user.has_perm('project.delete_asset'):
                return HttpResponseForbidden("You do not have permission.")
            action = "delete"
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('suggestions:suggestions'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for item in id_lst:
            if action == "delete":
                try:
                    s_obj = Asset.objects.get(uuid=item, scope='external').delete()
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue # take next item
            elif action == "ignore":
                try:
                    s_obj = Asset.objects.get(uuid=item, scope='external')
                    s_obj.ignore = True
                    s_obj.save()
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue # take next item
            elif action == "monitor":
                try:
                    s_obj = Asset.objects.get(uuid=item, scope='external')
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue # take next item
                if s_obj.type in ['certificate', 'domain']:
                    # check if entry already exists
                    try:
                        m_obj = Asset.objects.get(uuid=s_obj.uuid)
                    except Asset.DoesNotExist:
                        # copy to asset table
                        m_obj = Asset()
                        m_obj.related_keyword = s_obj.related_keyword
                        m_obj.related_project = s_obj.related_project
                        m_obj.value = s_obj.value
                        m_obj.uuid = s_obj.uuid
                        m_obj.source = s_obj.source
                        m_obj.creation_time = s_obj.creation_time
                        m_obj.description = s_obj.description
                        m_obj.link = s_obj.link
                        m_obj.save()
                    # hide from suggestions
                    s_obj.monitor = True
                    s_obj.save()
                    messages.info(request, 'Added %s to the monitoring' % s_obj.value)
                else:
                    messages.error(request, 'Unsupported finding type: %s' % s_obj.type)
                    continue
        # redirect to suggestion list
        return redirect(reverse('suggestions:suggestions'))
    else:
        prj = Project.objects.get(id=request.session['current_project']['prj_id'])
        context['all_count'] = prj.asset_set.filter(ignore=False).count()
        context['secondleveldomain_count'] = prj.asset_set.filter(type='domain', subtype='domain', ignore=False).count()
        context['starreddomain_count'] = prj.asset_set.filter(type='starred_domain', ignore=False).count()
        context['ip_count'] = prj.asset_set.filter(type='ip', ignore=False).count()
        context['activetab'] = 'domain'
    return render(request, 'suggestions/list_suggestions.html', context)


@login_required
def manual_add_suggestion(request):
    """Manually add a suggestion with XSS prevention"""
    if not request.user.has_perm('project.add_asset'):
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
    return redirect(reverse('suggestions:suggestions'))


@login_required
def ignored_suggestions(request):
    """view all ignored suggestions
    """
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    # check for POST request
    if request.method == 'POST':
        # determine action "move" or "delete"
        if "btnmove" in request.POST:
            if not request.user.has_perm('project.change_asset'):
                return HttpResponseForbidden("You do not have permission.")
            action = 'move'
        elif "btndelete" in request.POST:
            if not request.user.has_perm('project.delete_asset'):
                return HttpResponseForbidden("You do not have permission.")
            action = 'delete'
        else:
            messages.error(request, 'Unknown action received!')
            return redirect(reverse('suggestions:ignored_suggestions'))
        # get UUIDs of items
        id_lst = request.POST.getlist('id[]')
        for item in id_lst:
            if action == 'delete':
                try:
                    s_obj = Asset.objects.get(uuid=item, scope='external').delete()
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue
            elif action == 'move':
                try:
                    s_obj = Asset.objects.get(uuid=item, scope='external')
                    s_obj.ignore = False
                    s_obj.save()
                except Asset.DoesNotExist:
                    messages.error(request, 'Unknown Suggestion: %s' % item)
                    continue
        # redirect to ignore list
        return redirect(reverse('suggestions:ignored_suggestions'))
    return render(request, 'suggestions/list_ignored_suggestions.html', context)

@login_required
def delete_suggestion(request, uuid):
    """remove a suggestion
    """
    if not request.user.has_perm('project.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external').delete()
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
    return redirect(reverse('suggestions:suggestions'))

@login_required
def delete_suggestion_ignored(request, uuid):
    """remove a suggestion from ignored view
    """
    if not request.user.has_perm('project.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external').delete()
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:ignored_suggestions'))
    return redirect(reverse('suggestions:ignored_suggestions'))

@login_required
def monitor_suggestion(request, uuid):
    """move a suggestion to the monitored asset list
    """
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external')
        if s_obj.type in ['certificate', 'domain']:
            s_obj.monitor = True
            s_obj.save()
            messages.info(request, 'Added %s to the monitoring' % s_obj.value)
            return redirect(reverse('suggestions:suggestions'))
        else:
            messages.error(request, 'Unsupported finding type: %s' % s_obj.type)
            return redirect(reverse('suggestions:suggestions'))
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
        

# @login_required
# def monitor_all_unique_domains_derprecated(request):
#     """Monitor all domains that are active and that do not redirect to another domain
#     """
#     if not request.user.has_perm('project.add_asset'):
#         return HttpResponseForbidden("You do not have permission.")
    
#     context = {'projectid': request.session['current_project']['prj_id']}
#     s_objs = Asset.objects.filter(scope='external').exclude(active=False).exclude(ignore=True)

#     for s_obj in s_objs:
#         m_obj, _ = Asset.objects.get_or_create(uuid=s_obj.uuid,
#             defaults = {
#                 "related_keyword": s_obj.related_keyword,
#                 "related_project": s_obj.related_project,
#                 "value": s_obj.value,
#                 "source": s_obj.source,
#                 "creation_time": s_obj.creation_time,
#                 "description": s_obj.description,
#                 "link": s_obj.link,
#                 "monitor": True,
#             }
#         )
#         # hide from suggestions
#         s_obj.monitor = True
#         s_obj.save()

#     messages.info(request, f"Added {len(s_objs)} domains to the monitoring")
#     return redirect(reverse('suggestions:suggestions'))

@login_required
def ignore_suggestion(request, uuid):
    """move suggestion to the ignore list
    """
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external')
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:suggestions'))
    s_obj.ignore = True
    s_obj.save()
    return redirect(reverse('suggestions:suggestions'))

@login_required
def reactivate_suggestion(request, uuid):
    """reactivate an ignored suggestion
    """
    if not request.user.has_perm('project.change_suggestion'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        s_obj = Asset.objects.get(uuid=uuid, scope='external')
    except Asset.DoesNotExist:
        messages.error(request, 'Unknown Suggestion: %s' % uuid)
        return redirect(reverse('suggestions:ignored_suggestions'))
    s_obj.ignore = False
    s_obj.save()
    return redirect(reverse('suggestions:ignored_suggestions'))

@login_required
def delete_all_suggestions(request):
    """delete all suggestions in given project
    """
    if not request.user.has_perm('project.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('suggestions:suggestions'))
    # delete all suggestions
    prj_obj.suggestion_set.all().delete()
    return redirect(reverse('suggestions:suggestions'))

@login_required
def upload_suggestions(request):
    if not request.user.has_perm('project.add_asset'):
        return HttpResponseForbidden("You do not have permission.")
        
    context = {'projectid': request.session['current_project']['prj_id']}
    try:
        prj_obj = Project.objects.get(id=context['projectid'])
    except Exception as error:
        messages.error(request, 'Unknown Project: %s' % error)
        return redirect(reverse('suggestions:suggestions'))
    
    return upload_domains_from_file(request, prj_obj, 'suggestions:suggestions')


# @login_required
# def scan_redirects(request):
#     if not request.user.has_perm('project.change_suggestion'):
#         return HttpResponseForbidden("You do not have permission.")
    
#     context = {'projectid': request.session['current_project']['prj_id']}
#     messages.info(request, 'Domain redirection scan against monitored suggested domains has been triggered in the background. (check jobs)')

#     try:
#         # Get the project ID from the session
#         projectid = context['projectid']

#         # Define a function to run the command in a separate thread
#         def run_command():
#             try:
#                 # call_command('get_domain_redirect', projectid=projectid)
#                 command = 'get_domain_redirect'
#                 args = f'--projectid {projectid}'
#                 run_job(command, args, projectid, request.user)
#             except Exception as e:
#                 print(f"Error running get_domain_redirect: {e}")

#         # Start the thread
#         thread = threading.Thread(target=run_command)
#         thread.start()

#     except Exception as e:
#         messages.error(request, f'Error: {e}')
#     return redirect(reverse('suggestions:suggestions'))

@login_required
def scan_suggestions(request):
    if not request.user.has_perm('project.change_suggestion'):
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

    return redirect(reverse('suggestions:suggestions'))

@login_required
def export_suggestions_csv(request):
    """Export all suggestions for the current project as a CSV file for download."""
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    project_id = request.session['current_project']['prj_id']

    return export_assets_csv(project_id, monitored_only=False, scope='external')
