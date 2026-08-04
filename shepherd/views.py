from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from project.models import Project
from keywords.models import Keyword

@login_required
def home(request):
    context = {}
    # number of projects
    prj = Project.objects.all().count()
    context['projects'] = prj
    # number of keywords
    kw = Keyword.objects.all().count()
    context['keywords'] = kw
    #request.session['current_project'] = None
    return render(request, 'shepherd/index.html', context)
