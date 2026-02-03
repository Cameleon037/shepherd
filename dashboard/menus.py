# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem


def top_dashboard(request):
    return '<span class="glyphicon glyphicon-stats" aria-hidden="true"></span> Dashboard'


Menu.add_item(
    "main",
    MenuItem(
        top_dashboard,
        reverse("dashboard:dashboard"),
        weight=15,
    ),
)
