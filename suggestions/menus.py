# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_inventory(request):
    return '<span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span> Inventory'

inventory_children = (
    MenuItem("Assets", reverse("findings:assets"), weight=10),
    MenuItem("DNS Records", reverse("findings:dns_records"), weight=20),
    MenuItem("Web Endpoints", reverse("findings:web_endpoints"), weight=30),
    MenuItem("Ports", reverse("findings:nmap_results"), weight=15),
)

Menu.add_item("suggestions", MenuItem(top_inventory,
    "#",  # No direct URL for the parent menu
    weight=20,
    children=inventory_children
    )
)
