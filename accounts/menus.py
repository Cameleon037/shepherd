# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def profile_title(request):
    name = request.user.username
    return "Logout (%s)" % name

def top_user(request):
    return '<span class="glyphicon glyphicon-cog" aria-hidden="true"></span> Preferences'

def user_management_title(request):
    return "User Management"

user_management_children = (
    MenuItem("Manage Users",
             reverse("admin:auth_user_changelist"),
             weight=1),
    MenuItem("Add User",
             reverse("admin:auth_user_add"),
             weight=2),
)

Menu.add_item("accounts", MenuItem(user_management_title,
    reverse("admin:index"),
    weight=5,
    check=lambda request: request.user.is_superuser,
    children=user_management_children
))

sharing_children = (
    MenuItem("Change Password",
            reverse("accounts:change_password"),
            weight=1
        ),
    MenuItem("API Key",
            reverse("accounts:api_key"),
            weight=2
        ),
    MenuItem("API Docs",
            reverse("swagger-ui"),
            weight=3
        ),
    #MenuItem("Notes",
    #        reverse("accounts:list_notes"),
    #        weight=3
    #    ),
    MenuItem(profile_title,
            reverse("accounts:logout"),
            weight=10
        ),
)

Menu.add_item("accounts", MenuItem(top_user,
    reverse("accounts:login"),
    weight=10,
    children=sharing_children
    )
)



#sharing_children_mgmt = (
#    MenuItem("Organizations",
#        reverse("accounts:list_organizations"),
#        weight=10
#    ),
#    MenuItem("Users",
#        reverse("accounts:list_users"),
#        weight=5
#    ),
#)


#Menu.add_item("usermgmt", MenuItem("User Management",
#    reverse("accounts:list_users"),
#    weight=10,
#    children=sharing_children_mgmt)
#)

