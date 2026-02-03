from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse


class EnsureProjectMiddleware:
    """
    Redirect authenticated users to the project selection page when they try to
    access project-scoped views without having selected a project first.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.project_list_url = reverse('projects:projects')
        default_prefixes = [
            '/projects/',
            '/dashboard/',
            '/accounts/',
            '/oidc/',
            '/admin/',
            '/static/',
            '/media/',
            '/api/',
            '/favicon.ico',
        ]
        custom_prefixes = getattr(settings, 'PROJECT_SELECTION_EXEMPT_PATH_PREFIXES', [])
        self.exempt_prefixes = default_prefixes + list(custom_prefixes)

    def __call__(self, request):
        if self._requires_project(request):
            messages.warning(request, "Select a project before accessing this link.")
            return redirect(self.project_list_url)
        return self.get_response(request)

    def _requires_project(self, request):
        if not request.user.is_authenticated:
            return False

        current_project = request.session.get('current_project')
        if current_project:
            return False

        path = request.path or '/'
        if path == '/':
            return False

        # Allow explicit project selection paths or any exempt prefix
        for prefix in self.exempt_prefixes:
            if path.startswith(prefix):
                return False

        return True

