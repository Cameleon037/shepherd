from django.db import models


class Job(models.Model):
    COMMAND_CHOICES = [
        ('get_domain_redirect', 'Get Domain Redirect'),
        ('scan_nmap', 'Scan Nmap'),
        # ...add more as needed
    ]

    related_project = models.ForeignKey("project.Project", on_delete=models.CASCADE)  # relation to the project
    command = models.CharField(max_length=100, choices=COMMAND_CHOICES)
    args = models.TextField(blank=True, default='')

    status = models.CharField(max_length=20, default='pending')  # pending, running, finished, failed
    output = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    user = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        db_table = 'project_job'
