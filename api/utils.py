from django.db.models import Q


def get_ordering_vars(query_params, default_column=None, default_direction=''):
    """
    Returns column and direction to order/sort a datatable. Reads from requests query params, as posted
    by Datatables AJAX calls
    :return: Column and direction. Column = None indicates no ordering
    """
    if 'order[0][column]' in query_params and 'order[0][dir]' in query_params:
        order_by_column = query_params['columns[{idx}][data]'.format(idx=str(query_params['order[0][column]']))]
        #if order_by_column == 'short_filename':
        #    order_by_column = 'filename'
        #if order_by_column == 'short_ftype':
        #    order_by_column = 'ftype'
        #if order_by_column == "notifyonhit":  # changing to annotated column which deals with many2many sorting
        #    order_by_column = "notify"
        if query_params['order[0][dir]'] == 'desc':
            order_direction = '-'
        else:
            order_direction = ''
    else:
        order_by_column = default_column
        order_direction = default_direction

    return order_by_column, order_direction


def apply_search_filter(queryset, search_value, field_paths, min_length=1):
    """
    Apply global search filter to queryset with support for negative search (fields starting with !).
    
    Args:
        queryset: Django queryset to filter
        search_value: Search string (if starts with !, it's a negative search)
        field_paths: List of Django field paths (e.g., ["value__icontains", "description__icontains"])
        min_length: Minimum length of search value to apply filter (default: 1)
    
    Returns:
        Filtered queryset
    
    Examples:
        # Global search across multiple fields
        queryset = apply_search_filter(queryset, "test", [
            "value__icontains", "description__icontains", "source__icontains"
        ])
        
        # Negative search (exclude)
        queryset = apply_search_filter(queryset, "!test", ["value__icontains", "description__icontains"])
    """
    if not search_value:
        return queryset
    
    # Check for negative search
    is_negative = search_value.startswith('!')
    if is_negative:
        search_value = search_value[1:]  # Remove the !
    
    # Check length after stripping the ! prefix
    if not search_value or len(search_value) < min_length:
        return queryset
    
    # Build Q objects for global search across multiple fields
    q_objects = Q()
    for field_path in field_paths:
        q_objects |= Q(**{field_path: search_value})
    
    if is_negative:
        queryset = queryset.exclude(q_objects)
    else:
        queryset = queryset.filter(q_objects)
    
    return queryset


def apply_column_search(queryset, search_value, field_path, min_length=1):
    """
    Apply a single column search filter with negative search support.
    
    Args:
        queryset: Django queryset to filter
        search_value: Search string (if starts with !, it's a negative search)
        field_path: Django field path (e.g., "value__icontains", "domain__name__icontains")
        min_length: Minimum length of search value to apply filter (default: 1)
    
    Returns:
        Filtered queryset
    """
    if not search_value:
        return queryset
    
    # Check for negative search
    is_negative = search_value.startswith('!')
    if is_negative:
        search_value = search_value[1:]  # Remove the !
    
    # Check length after stripping the ! prefix
    if not search_value or len(search_value) < min_length:
        return queryset
    
    if is_negative:
        queryset = queryset.exclude(**{field_path: search_value})
    else:
        queryset = queryset.filter(**{field_path: search_value})
    
    return queryset
