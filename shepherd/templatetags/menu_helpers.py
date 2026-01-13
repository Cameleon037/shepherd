from django import template

register = template.Library()

@register.filter
def is_menu_active(menu_item, request_path):
    """
    Determine if a menu item should be highlighted as active.
    For dropdown menus (with children), check if any child URL matches.
    For regular menus, check if the URL is contained in the path.
    """
    # Exact match
    if menu_item.url == request_path:
        return True
    
    # For dropdown menus with children, check child URLs first
    if hasattr(menu_item, 'children') and menu_item.children:
        for child in menu_item.children:
            if child.url == request_path:
                return True
        # Don't do substring matching for dropdown menus with placeholder URLs
        return False
    
    # For regular menus without children, do substring matching
    # But exclude placeholder URLs like "#"
    # Special case: Don't highlight Inventory menu if we're on Security Scans sub-items
    if (menu_item.url in request_path and 
        request_path != "/" and 
        menu_item.url != "/" and 
        menu_item.url != "#"):
        
        # Special handling for findings menu conflict
        # If we're on a findings sub-path and this is the inventory menu, don't highlight
        if (menu_item.url == "/findings/" and 
            request_path.startswith("/findings/") and 
            request_path != "/findings/"):
            # Check if this looks like a Security Scans sub-item
            security_scans_paths = [
                "/findings/control-center/",
                "/findings/nmap/results/",
                "/findings/scanners/results", 
                "/findings/httpx/results/",
                "/findings/data_leaks/"
            ]
            if any(request_path.startswith(path) for path in security_scans_paths):
                return False
        
        return True
    
    return False
