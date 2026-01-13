# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_discovery(request):
    return '<span class="glyphicon glyphicon-search" aria-hidden="true"></span> Discovery'

discovery_children = (
    MenuItem("Discovery Keywords", reverse("keywords:keywords"), weight=5),
    MenuItem("Control Center", reverse("keywords:discovery_control_center"), weight=10),
    MenuItem("Asset Suggestions", reverse("suggestions:suggestions"), weight=20),
    MenuItem("Assets Ignored ", reverse("suggestions:ignored_suggestions"), weight=30),
)

Menu.add_item("keywords", MenuItem(top_discovery,
    "#",  # No direct URL for the parent menu
    weight=10,
    children=discovery_children
    )
)
