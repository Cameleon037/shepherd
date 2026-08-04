# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem
from jobs.models import Job

def top_jobs(request):
    running_count = Job.objects.filter(status="running").count()
    icon_html = '<span class="glyphicon glyphicon-tasks" aria-hidden="true"></span>'
    if running_count > 0:
        icon_html += f' <span class="badge" style="background-color:#337ab7;">{running_count}</span>'
    return f'{icon_html} Jobs'

sharing_children = (
    MenuItem("Jobs", reverse("jobs:jobs"), weight=10),
    # MenuItem("Scheduled Jobs", "/admin/django_celery_beat/periodictask/", weight=15),
    MenuItem("Scheduled Jobs", reverse("jobs:scheduled_jobs"), weight=15),
)

Menu.add_item("jobs", MenuItem(top_jobs,
    reverse("jobs:jobs"),
    weight=10,
    children=sharing_children
    )
)
