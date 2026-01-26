from django.http import HttpResponseForbidden
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils.html import escape

from .models import Project
from .forms import AddProjectForm

@login_required
def projects(request):
    if not request.user.has_perm('project.view_project'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {'projectform': AddProjectForm(), 'num_total_domains': 0, 'num_total_subdomains': 0, 'num_total_ipaddresses': 0, 'num_ignored_domains': 0, 'num_ignored_subdomains': 0, 'num_ignored_ipaddresses': 0}
    if 'current_project' in request.session and request.session['current_project'] is not None:
        # load project
        prj = Project.objects.get(id=request.session['current_project']['prj_id'])
        #print(prj)
        context['project_name'] = prj.projectname
        # get suggestions
        context['num_total_domains'] = prj.asset_set.filter(type='domain').count()
        context['num_ignored_domains'] = prj.asset_set.filter(type='domain', ignore=True).count()
        context['num_total_total'] = context['num_total_domains']+context['num_total_subdomains']+context['num_total_ipaddresses']
        context['num_ignored_total'] = context['num_ignored_domains']+context['num_ignored_subdomains']+context['num_ignored_ipaddresses']

    return render(request, 'projects/list_projects.html', context)

@login_required
def select_project(request, projectid):
    if not request.user.has_perm('project.view_project'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {}
    try:
        prj_obj = Project.objects.get(id=projectid)
        prj_name = prj_obj.projectname
        prj_id = prj_obj.id
    except Project.DoesNotExist:
        print('ERROR: project not existing')
        prj_obj = None
        prj_name = None
        prj_id = None
    if prj_obj is not None:
        request.session['current_project'] = {'prj_id': prj_id, 'prj_name': prj_name}
    else:
        request.session['current_project'] = None
    #return render(request, 'projects/list_projects.html', context)
    return redirect(reverse('projects:projects'))

@login_required
def delete_project(request, projectid):
    """delete given project
    """
    if not request.user.has_perm('project.delete_project'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {}
    try:
        prj_obj = Project.objects.get(id=projectid)
        prj_obj.delete()
    except Project.DoesNotExist:
        print('ERROR: project not existing')
    request.session['current_project'] = None
    return redirect(reverse('projects:projects'))

@login_required
def unselect_project(request):
    """unselect current project
    """
    if not request.user.has_perm('project.view_project'):
        return HttpResponseForbidden("You do not have permission.")
    
    context = {}
    request.session['current_project'] = None
    return redirect(reverse('projects:projects'))

@login_required
def add_project(request):
    if not request.user.has_perm('project.add_project'):
        return HttpResponseForbidden("You do not have permission.")
    
    if request.method == 'POST':
        form = AddProjectForm(request.POST)
        if form.is_valid():
            # Escape all cleaned_data fields before saving
            project = form.save(commit=False)
            for field, value in form.cleaned_data.items():
                if isinstance(value, str):
                    setattr(project, field, escape(value))
            project.save()
            messages.info(request, "Project successfully added")
    return redirect(reverse('projects:projects'))
