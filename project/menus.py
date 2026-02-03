# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_project(request):
    return '<span class="glyphicon" aria-hidden="true"></span> Projects'

Menu.add_item("main", MenuItem(top_project,
    reverse("projects:projects"),
    weight=12
    )
)
