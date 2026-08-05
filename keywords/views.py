# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST

from project.models import Project
from keywords.models import Keyword
from assets.models import Asset
from keywords.forms import AddKeywordForm
import threading

from django.utils.html import escape
from jobs.utils import run_job

@login_required
def keywords(request):
    if not request.user.has_perm('keywords.view_keyword'):
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
    if not request.user.has_perm('keywords.change_keyword'):
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
    if not request.user.has_perm('keywords.delete_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    try:
        kw_obj = Keyword.objects.get(id=keywordid).delete()
    except Keyword.DoesNotExist:
        return redirect(reverse('keywords:keywords'))
    return redirect(reverse('keywords:keywords'))

@login_required
def add_keyword(request):
    if not request.user.has_perm('keywords.add_keyword'):
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
@require_POST
def upload_ransomlook_suppliers(request):
    """Upload RansomLook suppliers from a text file"""
    if not request.user.has_perm('keywords.add_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session.get('current_project', {}).get('prj_id')
    if not project_id:
        messages.error(request, 'No project selected.')
        return redirect(reverse('keywords:keywords'))
    
    try:
        prj_obj = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        messages.error(request, 'Unknown Project.')
        return redirect(reverse('keywords:keywords'))
    
    if request.method == "POST" and request.FILES.get("suppliers_file"):
        suppliers_file = request.FILES["suppliers_file"]
        
        # Read all lines into memory
        lines = [escape(line.decode("utf-8").strip()) for line in suppliers_file if line.strip()]
        
        def process_suppliers(lines, prj_obj):
            # Delete all existing ransomlook_supplier keywords for this project
            deleted_count = Keyword.objects.filter(
                related_project=prj_obj,
                ktype='ransomlook_supplier'
            ).delete()[0]
            
            # Create new keywords from the uploaded file
            created_cnt = 0
            for supplier in lines:
                if supplier:
                    # Create keyword with ktype='ransomlook_supplier'
                    keyword_data = {
                        'keyword': supplier,
                        'ktype': 'ransomlook_supplier',
                        'description': 'RansomLook supplier - uploaded from file',
                        'related_project': prj_obj,
                        'enabled': True
                    }
                    Keyword.objects.create(**keyword_data)
                    created_cnt += 1
            
            return deleted_count, created_cnt
        
        # Start processing in a background thread
        def process_in_thread():
            try:
                deleted, created = process_suppliers(lines, prj_obj)
                # Note: Messages won't work in background thread, but processing will complete
            except Exception as e:
                print(f"Error processing RansomLook suppliers: {e}")
        
        thread = threading.Thread(target=process_in_thread)
        thread.start()
        messages.success(request, f"RansomLook suppliers are being uploaded in the background ({len(lines)} suppliers). Previous suppliers will be replaced. Please refresh the page after a while.")
    else:
        messages.error(request, "No file uploaded.")
    
    return redirect(reverse('keywords:keywords'))

@login_required
def scan_keywords(request):
    if not request.user.has_perm('assets.add_asset'):
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

        if "ransomlook" in request.POST:
            messages.info(request, 'RansomLook scan against monitored keywords has been triggered in the background.')
            try:
                projectid = context['projectid']
                def run_command():
                    try:
                        command = 'scan_ransomlook'
                        args = f'--projectid {projectid}'
                        run_job(command, args, projectid, request.user)
                    except Exception as e:
                        print(f"Error running scan_ransomlook: {e}")
                thread = threading.Thread(target=run_command)
                thread.start()
            except Exception as e:
                messages.error(request, f'Error: {e}')


    return redirect(reverse('keywords:keywords'))


@login_required
def discovery_control_center(request):
    """Discovery Control Center - manage keyword-based discovery scans"""
    if not request.user.has_perm('keywords.view_keyword'):
        return HttpResponseForbidden("You do not have permission.")
    
    project_id = request.session.get('current_project', {}).get('prj_id', None)
    keywords = []
    if project_id:
        keywords = Keyword.objects.filter(
            related_project_id=project_id,
            enabled=True
        ).exclude(ktype='ransomlook_supplier').order_by('keyword')
    
    context = {
        'projectid': project_id,
        'keywords': keywords,
    }
    return render(request, 'keywords/discovery_control_center.html', context)
