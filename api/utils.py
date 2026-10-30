from django.db.models import Count, Q


TABLE_GROUP_FIELDS = {
    'assets.asset': {'value': 'value', 'source': 'source', 'tag': 'tag', 'scope': 'scope',
                     'owner': 'owner', 'monitor': 'monitor', 'active': 'active', 'endpoint_count': 'endpoint_count'},
    'findings.finding': {'asset_name': 'asset_name', 'name': 'name', 'type': 'type',
                         'source': 'source', 'severity': 'severity', 'status': 'status',
                         'keyword': 'keyword__keyword'},
    'findings.dnsrecord': {'asset_value': 'related_asset__value', 'record_type': 'record_type'},
    'findings.port': {'asset_name': 'asset_name', 'port': 'port'},
    'findings.screenshot': {'technologies': 'technologies', 'status_code': 'status_code',
                            'webserver': 'webserver', 'asset_source': 'asset__source'},
    'findings.endpoint': {'asset_value': 'asset__value', 'technologies': 'technologies'},
    'jobs.job': {'command': 'command', 'status': 'status', 'username': 'user__username'},
    'keywords.keyword': {'keyword': 'keyword', 'ktype': 'ktype', 'enabled': 'enabled'},
    'project.project': {'projectname': 'projectname'},
}


def apply_table_grouping(rows, group_by):
    """Keep complete groups contiguous before pagination, retaining row ordering.

    Allow only known display fields, never arbitrary ORM paths from the request.
    List responses (grouped keywords and schedules) use a stable in-memory sort.
    """
    if not group_by:
        return rows
    if isinstance(rows, list):
        if group_by not in ('keyword', 'enabled', 'name', 'task', 'schedule'):
            return rows
        return sorted(rows, key=lambda row: str(row.get(group_by) or ''))
    field = TABLE_GROUP_FIELDS.get(rows.model._meta.label_lower, {}).get(group_by)
    if not field or (field == 'endpoint_count' and field not in rows.query.annotations):
        return rows
    ordering = [name for name in rows.query.order_by if name.lstrip('-') != field]
    return rows.order_by(field, *ordering, 'pk')


def annotate_vulnerabilities(queryset):
    """Count visible, open findings identically for assets and suggestions."""
    return queryset.annotate(**{
        f'vuln_{severity}': Count(
            'finding', filter=Q(finding__severity=severity, finding__ignore=False) & ~Q(finding__status='fixed'),
            distinct=True,
        )
        for severity in ('critical', 'high', 'medium', 'low', 'info')
    })


def get_column_search(query_params, field, fallback_index):
    """Resolve column searches by field, retaining the legacy API index fallback."""
    if 'columns[0][data]' in query_params:
        for key, value in query_params.items():
            if key.startswith('columns[') and key.endswith('[data]') and value == field:
                return query_params.get(key[:-6] + '[search][value]')
        return None
    return query_params.get(f'columns[{fallback_index}][search][value]')


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
    """Match each comma-separated term across any field; ! excludes a term."""
    return apply_column_search_multi(queryset, search_value, field_paths, min_length=min_length)


def search_terms(search_value, delimiter=',', min_length=1):
    """Yield (term, excluded) using the shared table search syntax."""
    for segment in (search_value or '').split(delimiter):
        segment = segment.strip()
        excluded = segment.startswith('!')
        term = segment[1:].strip() if excluded else segment
        if term and len(term) >= min_length:
            yield term, excluded


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


def apply_column_search_multi(queryset, search_value, field_path, delimiter=',', min_length=1):
    """
    Apply column search with multiple comma-separated values; each segment can be
    "!value" (exclude) or "value" (include). E.g. "!a,!b" excludes rows where
    the field contains "a" and also excludes rows where it contains "b".

    field_path may be a single field path (e.g. "source__icontains") or a list of
    field paths (e.g. ["url__icontains", "technologies__icontains"]); for a list,
    each segment matches if any of the fields contains the value.

    Args:
        queryset: Django queryset to filter
        search_value: Search string; split on delimiter; each segment can start with ! for exclude
        field_path: Django field path or list of field paths
        delimiter: Split search_value on this (default: comma)
        min_length: Minimum length of each segment (after stripping !) to apply (default: 1)

    Returns:
        Filtered queryset
    """
    if not search_value:
        return queryset
    field_paths = field_path if isinstance(field_path, (list, tuple)) else [field_path]
    for segment, is_negative in search_terms(search_value, delimiter, min_length):
        field_q = Q()
        for fp in field_paths:
            field_q |= Q(**{fp: segment})
        if is_negative:
            queryset = queryset.exclude(field_q)
        else:
            queryset = queryset.filter(field_q)
    return queryset
