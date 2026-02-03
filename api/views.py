from datetime import datetime, timedelta

from django.shortcuts import render
from django.http import HttpResponseForbidden, JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Q, Prefetch, Count, F, Case, When, IntegerField
from django.conf import settings
from django.utils.timezone import make_aware

from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication, TokenAuthentication

from api.pagination import CustomPaginator
from api.serializer import JobSerializer, ProjectSerializer, KeywordSerializer, SuggestionSerializer, AssetSerializer, FindingSerializer, PortSerializer, ScreenshotSerializer, DNSRecordSerializer, EndpointSerializer
from api.utils import get_ordering_vars, apply_search_filter, apply_column_search

from project.models import Project, Keyword, Asset, Job, DNSRecord
from findings.models import Finding, Port, Screenshot, Endpoint
from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule, ClockedSchedule

# Create your views here.

##### PROJECTS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_projects(request, format=None):
    """List all projects
    """
    if not request.user.has_perm('project.view_project'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    search_value = request.query_params.get('search[value]', None)
    
    ### create queryset
    queryset = Project.objects.all()
    
    ### filter by search value
    queryset = apply_search_filter(
        queryset, search_value,
        ['projectname__icontains', 'description__istartswith'],
        min_length=1
    )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='last_modified',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        order = f"{'-' if order_direction == '-' else ''}{order_by_column}"
        queryset = queryset.order_by(order)

    paginator = CustomPaginator()
    prjs = paginator.paginate_queryset(queryset, request)
    serializer = ProjectSerializer(instance=prjs, many=True)

    return paginator.get_paginated_response(serializer.data)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def create_project(request, format=None):
    """Create project via API
    """
    if not request.user.has_perm('project.add_project'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    prj_serializer = ProjectSerializer(data=request.data)
    if prj_serializer.is_valid():
        prj_serializer.save()
        result = {'message': 'Project successfully created', 'status': 'success'}
    else:
        result = {'message': 'Project failed to create: %s' % (prj_serializer.errors), 'status': 'failure'}
    return JsonResponse(result)


##### END PROJECTS ###############

##### SUGGESTIONS ################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_suggestions(request, projectid, selection, vtype, format=None):
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### get search parameters
    search_value = request.query_params.get('columns[1][search][value]', None)
    search_source = request.query_params.get('columns[2][search][value]', None)
    search_tag = request.query_params.get('columns[3][search][value]', None)
    search_description = request.query_params.get('columns[4][search][value]', None)
    search_redirect_to = request.query_params.get('columns[5][search][value]', None)
    search_creation_date = request.query_params.get('columns[6][search][value]', None)
    search_monitor = request.query_params.get('columns[7][search][value]', None)
    search_active = request.query_params.get('columns[8][search][value]', None)
    search_ip = request.query_params.get('columns[9][search][value]', None)
    search_owner = request.query_params.get('columns[10][search][value]', None)
    search_scope = request.query_params.get('columns[11][search][value]', None)
    
    ### create queryset
    if selection in ['ignored']:
        queryset = prj.asset_set.filter(ignore=True)
    else:
        queryset = prj.asset_set.filter(ignore=False)  # Do not display ignored suggestions

    if vtype in ['all']:
        # Show all types - no filter
        pass
    elif vtype in ['domain']:
        queryset = queryset.filter(type='domain')
    elif vtype in ['starred_domain']:
        queryset = queryset.filter(type=vtype)
    elif vtype in ['second_level_domain']:
        queryset = queryset.filter(type='domain', subtype='domain')
    elif vtype in ['ip']:
        queryset = queryset.filter(type='ip')
    
    ### filter by search value
    queryset = apply_column_search(queryset, search_value, 'value__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_source, 'source__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_tag, 'tag__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_description, 'description__icontains', min_length=1)
    
    ### Don't use select_related as it causes performance issues with self-referencing FK
    queryset = apply_column_search(queryset, search_redirect_to, 'redirects_to__value__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_creation_date, 'creation_time__icontains', min_length=1)
    
    if search_monitor is not None and search_monitor != '':
        is_negative = search_monitor.startswith('!')
        monitor_value = search_monitor.lstrip('!').lower()
        if monitor_value == 'true':
            if is_negative:
                queryset = queryset.exclude(monitor=True)
            else:
                queryset = queryset.filter(monitor=True)
        elif monitor_value == 'false':
            if is_negative:
                queryset = queryset.exclude(monitor=False)
            else:
                queryset = queryset.filter(monitor=False)
        elif monitor_value == 'none':
            if is_negative:
                queryset = queryset.exclude(monitor__isnull=True)
            else:
                queryset = queryset.filter(monitor__isnull=True)
    
    if search_active is not None and search_active != '':
        is_negative = search_active.startswith('!')
        active_value = search_active.lstrip('!').lower()
        if active_value == 'true':
            if is_negative:
                queryset = queryset.exclude(active=True)
            else:
                queryset = queryset.filter(active=True)
        elif active_value == 'false':
            if is_negative:
                queryset = queryset.exclude(active=False)
            else:
                queryset = queryset.filter(active=False)
        elif active_value == 'none':
            if is_negative:
                queryset = queryset.exclude(active__isnull=True)
            else:
                queryset = queryset.filter(active__isnull=True)
    
    # IP search (can be IPv4 or IPv6)
    queryset = apply_search_filter(
        queryset, search_ip,
        ['ipv4__icontains', 'ipv6__icontains'],
        min_length=1
    )
    
    queryset = apply_column_search(queryset, search_owner, 'owner__icontains', min_length=1)
    
    # Filter by scope if provided
    if search_scope and search_scope != "":
        if search_scope.lower() == 'external':
            queryset = queryset.filter(scope='external')
        elif search_scope.lower() == 'internal':
            queryset = queryset.filter(scope='internal')
        # 'all' returns all, no additional filter

    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='creation_time',
                                                         default_direction='-')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')
    
    suggestions = paginator.paginate_queryset(queryset, request)
    serializer = SuggestionSerializer(instance=suggestions, many=True)
    # Modify the serialized data to include the redirects_to_value
    serialized_data = serializer.data
    
    # Efficiently fetch redirect values for objects that have them
    redirect_ids = [s.redirects_to_id for s in suggestions if s.redirects_to_id]
    redirect_values = {}
    if redirect_ids:
        redirect_assets = Asset.objects.filter(uuid__in=redirect_ids).only('uuid', 'value')
        redirect_values = {asset.uuid: asset.value for asset in redirect_assets}
    
    # Add redirect values to serialized data
    for item, suggestion in zip(serialized_data, suggestions):
        item['redirects_to'] = redirect_values.get(suggestion.redirects_to_id, None)

    return paginator.get_paginated_response(serialized_data)


##### END SUGGESTIONS ###########


##### ASSETS ###############
@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_assets(request, projectid, selection, format=None):
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "status": True,
            "code": 200,
            "next": None,
            "previous": None,
            "count": 0,
            "iTotalRecords": 0,
            "iTotalDisplayRecords": 0,
            "results": []
        })

    ### get search parameters
    search_value = request.query_params.get('search[value]', None)
    search_columns = {
        'value': request.query_params.get('columns[1][search][value]', None),
        'vulns': request.query_params.get('columns[2][search][value]', None),
        'tag': request.query_params.get('columns[3][search][value]', None),
        'source': request.query_params.get('columns[4][search][value]', None),
        'description': request.query_params.get('columns[5][search][value]', None),
        'last_scan_time': request.query_params.get('columns[6][search][value]', None),
        'creation_time': request.query_params.get('columns[7][search][value]', None),
        'ip': request.query_params.get('columns[8][search][value]', None),
        'owner': request.query_params.get('columns[9][search][value]', None),
        'scope': request.query_params.get('columns[10][search][value]', None),
    }

    ### create queryset
    if selection in ['monitored']:
        queryset = prj.asset_set.filter(monitor=True, ignore=False)
    else:
        queryset = prj.asset_set.filter(monitor=False, ignore=False)

    # Annotate vulnerabilities
    queryset = queryset.annotate(
        vuln_info=Count('finding', filter=Q(finding__severity='info')),
        vuln_critical=Count('finding', filter=Q(finding__severity='critical')),
        vuln_high=Count('finding', filter=Q(finding__severity='high')),
        vuln_medium=Count('finding', filter=Q(finding__severity='medium')),
        vuln_low=Count('finding', filter=Q(finding__severity='low'))
    )

    # Filter by scope if provided
    if search_columns['scope'] and search_columns['scope'] != "":
        if search_columns['scope'].lower() == 'external':
            queryset = queryset.filter(scope='external')
        elif search_columns['scope'].lower() == 'internal':
            queryset = queryset.filter(scope='internal')
        # 'all' returns all, no additional filter

    ### filter by global search value
    queryset = apply_search_filter(
        queryset, search_value,
        ['value__icontains', 'description__icontains', 'source__icontains',
         'ipv4__icontains', 'ipv6__icontains', 'owner__icontains'],
        min_length=1
    )

    ### filter by column-specific search values
    queryset = apply_column_search(queryset, search_columns['value'], 'value__icontains')
    
    if search_columns['vulns']:
        # Map severity keywords to annotated fields
        severity_map = {
            'info': 'vuln_info',
            'critical': 'vuln_critical',
            'high': 'vuln_high',
            'medium': 'vuln_medium',
            'low': 'vuln_low',
        }
        severity_filter = search_columns['vulns'].lower().lstrip('!')
        is_negative = search_columns['vulns'].startswith('!')
        if severity_filter in severity_map:
            if is_negative:
                queryset = queryset.filter(**{f"{severity_map[severity_filter]}": 0})
            else:
                queryset = queryset.filter(**{f"{severity_map[severity_filter]}__gt": 0})

    queryset = apply_column_search(queryset, search_columns['tag'], 'tag__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_columns['source'], 'source__icontains')
    queryset = apply_column_search(queryset, search_columns['description'], 'description__icontains')
    queryset = apply_column_search(queryset, search_columns['last_scan_time'], 'last_scan_time__icontains')
    queryset = apply_column_search(queryset, search_columns['creation_time'], 'creation_time__icontains')
    
    # IP search (can be IPv4 or IPv6)
    if search_columns['ip']:
        queryset = apply_search_filter(
            queryset, search_columns['ip'],
            ['ipv4__icontains', 'ipv6__icontains'],
            min_length=1
        )
    
    queryset = apply_column_search(queryset, search_columns['owner'], 'owner__icontains', min_length=1)

    ### get variables
    order_by_column, order_direction = get_ordering_vars(
        request.query_params,
        default_column='creation_time',
        default_direction='-'
    )

    ### order queryset
    if order_by_column and order_by_column != "vulns":
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    ### paginate queryset
    assets = paginator.paginate_queryset(queryset, request)
    serializer = AssetSerializer(instance=assets, many=True)
    return paginator.get_paginated_response(serializer.data)


##### END ASSETS ###########

##### DNS RECORDS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_dns_records(request, projectid, format=None):
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "status": True,
            "code": 200,
            "next": None,
            "previous": None,
            "count": 0,
            "iTotalRecords": 0,
            "iTotalDisplayRecords": 0,
            "results": []
        })

    ### get search parameters
    search_asset = request.query_params.get('columns[1][search][value]', None)
    search_record_type = request.query_params.get('columns[2][search][value]', None)
    search_record_value = request.query_params.get('columns[3][search][value]', None)
    search_ttl = request.query_params.get('columns[4][search][value]', None)
    search_last_checked = request.query_params.get('columns[5][search][value]', None)

    ### create queryset - only for monitored assets
    queryset = DNSRecord.objects.filter(
        related_project=prj,
        related_asset__monitor=True,
        related_asset__ignore=False,
    ).select_related('related_asset')

    ### filter by search parameters
    queryset = apply_column_search(queryset, search_asset, 'related_asset__value__icontains', min_length=1)
    
    # Record type uses exact match (case-insensitive)
    if search_record_type:
        is_negative = search_record_type.startswith('!')
        record_type_value = search_record_type.lstrip('!')
        if len(record_type_value) > 0:
            if is_negative:
                queryset = queryset.exclude(record_type__iexact=record_type_value)
            else:
                queryset = queryset.filter(record_type__iexact=record_type_value)
    
    queryset = apply_column_search(queryset, search_record_value, 'record_value__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_ttl, 'ttl__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_last_checked, 'last_checked__icontains', min_length=1)

    ### get ordering variables
    order_by_column, order_direction = get_ordering_vars(
        request.query_params,
        default_column='last_checked',
        default_direction='-'
    )
    
    ### map frontend column names to database field names
    if order_by_column == 'asset_value':
        order_by_column = 'related_asset__value'
    elif order_by_column == 'asset_uuid':
        order_by_column = 'related_asset__uuid'
    
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    dns_records = paginator.paginate_queryset(queryset, request)
    serializer = DNSRecordSerializer(instance=dns_records, many=True)
    return paginator.get_paginated_response(serializer.data)

##### END DNS RECORDS ###########

##### WEB ENDPOINTS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_endpoints(request, projectid, format=None):
    if not request.user.has_perm('project.view_asset'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "status": True,
            "code": 200,
            "next": None,
            "previous": None,
            "count": 0,
            "iTotalRecords": 0,
            "iTotalDisplayRecords": 0,
            "results": []
        })

    ### get search parameters
    search_asset = request.query_params.get('columns[1][search][value]', None)
    search_url = request.query_params.get('columns[2][search][value]', None)
    search_technologies = request.query_params.get('columns[3][search][value]', None)
    search_date = request.query_params.get('columns[4][search][value]', None)

    ### create queryset - only for monitored assets
    queryset = Endpoint.objects.filter(
        domain__related_project=prj,
        domain__monitor=True,
        domain__ignore=False,
    ).select_related('domain')

    ### filter by search parameters
    queryset = apply_column_search(queryset, search_asset, 'domain__value__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_url, 'url__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_technologies, 'technologies__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_date, 'date__icontains', min_length=1)

    ### get ordering variables
    order_by_column, order_direction = get_ordering_vars(
        request.query_params,
        default_column='date',
        default_direction='-'
    )
    
    ### map frontend column names to database field names
    if order_by_column == 'asset_value':
        order_by_column = 'domain__value'
    elif order_by_column == 'asset_uuid':
        order_by_column = 'domain__uuid'
    
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    endpoints = paginator.paginate_queryset(queryset, request)
    serializer = EndpointSerializer(instance=endpoints, many=True)
    return paginator.get_paginated_response(serializer.data)

##### END WEB ENDPOINTS ###########

##### KEYWORDS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_keywords(request, projectid, selection, format=None):
    if not request.user.has_perm('project.view_keyword'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### get search parameters
    search_value = request.query_params.get('search[value]', None)
    
    ### create queryset
    if selection in ['enabled']:
        queryset = prj.keyword_set.all().filter(enabled=True).exclude(ktype='ransomlook_supplier')
    elif selection in ['disabled']:
        queryset = prj.keyword_set.all().filter(enabled=False).exclude(ktype='ransomlook_supplier')
    elif selection in ['suppliers']:
        queryset = prj.keyword_set.all().filter(ktype='ransomlook_supplier')
    else:
        queryset = prj.keyword_set.all().exclude(ktype='ransomlook_supplier')
    
    ### filter by search value
    queryset = apply_search_filter(
        queryset, search_value,
        ['keyword__icontains', 'description__istartswith'],
        min_length=1
    )
    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='ktype' if selection == 'all' else 'last_modified',
                                                         default_direction='')
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    elif selection == 'all':
        # Default sort by ktype for 'all' selection
        queryset = queryset.order_by('ktype')
    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = KeywordSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def add_keyword(request, format=None):
    """Add keywords to a project
    """
    if not request.user.has_perm('project.add_keyword'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    prjname = request.data.get('projectname', None)
    keywords = request.data.get('keywords', None)
    if prjname is not None:
        try:
            prj_obj = Project.objects.get(projectname=prjname)
        except Project.DoesNotExist:
            result = {'message': 'Given project does not exist', 'status': 'failure'}
            return JsonResponse(result)
    if keywords is None:
        result = {'message': 'No keywords given', 'status': 'failure'}
        return JsonResponse(result)
    if type(keywords)==type([]):
        for k in keywords:
            obj = {'related_project': prj_obj, 'keyword': k}
            kobj, created = Keyword.objects.get_or_create(**obj)
    elif type(keywords)==type(""):
        obj = {'related_project': prj_obj, 'keyword': keywords}
        kobj, created = Keyword.objects.get_or_create(**obj)
    else:
        result = {'message': 'Wrong datatype given: %s' % (type(keywords)), 'status': 'failure'}
        return JsonResponse(result)
    result = {'message': 'Keywords successfully created', 'status': 'success'}
    return JsonResponse(result)



##### END KEYWORDS ###############

##### PORTS ###############
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_ports(request, projectid, format=None):
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    # Fetch all active domains associated with the project
    active_domains = Asset.objects.filter(related_project=prj, monitor=True)

    # Define queryset to filter ports by active domains
    queryset = Port.objects.filter(domain__in=active_domains)

    # Get search parameters
    search_value = request.query_params.get('search[value]', None)
    queryset = apply_search_filter(
        queryset, search_value,
        ['port__icontains', 'banner__icontains', 'status__icontains',
         'product__icontains', 'cpe__icontains'],
        min_length=1
    )

    search_domain_name = request.query_params.get('columns[1][search][value]', None)
    search_port = request.query_params.get('columns[2][search][value]', None)
    search_banner = request.query_params.get('columns[3][search][value]', None)
    search_cpe = request.query_params.get('columns[4][search][value]', None)
    search_last_scan = request.query_params.get('columns[5][search][value]', None)

    ### filter by column-specific search values
    queryset = apply_column_search(queryset, search_domain_name, 'domain_name__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_port, 'port__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_banner, 'banner__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_cpe, 'cpe__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_last_scan, 'scan_date__icontains', min_length=1)

    # Get ordering variables
    order_by_column, order_direction = get_ordering_vars(request.query_params, default_column='scan_date', default_direction='-')

    # Order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    # Paginate queryset
    ports = paginator.paginate_queryset(queryset, request)
    serializer = PortSerializer(instance=ports, many=True)

    return paginator.get_paginated_response(serializer.data)

@api_view(['DELETE'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def delete_port(request, projectid, portid):
    if not request.user.has_perm('findings.delete_port'):
        return HttpResponseForbidden("You do not have permission to delete ports.")

    try:
        Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'error': 'Project not found'}, status=404)

    try:
        port_obj = Port.objects.get(id=portid, domain__related_project__id=projectid)
    except Port.DoesNotExist:
        return JsonResponse({'error': 'Port not found'}, status=404)

    port_obj.delete()
    return JsonResponse({'success': True})

##### END PORTS ###############


##### FINDINGS ###############

# @api_view(['GET'])
# @authentication_classes((SessionAuthentication, ))
# @permission_classes((IsAuthenticated,))
# def list_recent_findings(request, projectid, severity, format=None):
#     if not request.user.has_perm('findings.view_finding'):
#         return HttpResponseForbidden("You do not have permission to view this project.")
    
#     paginator = CustomPaginator()
#     if severity not in ['info', 'low', 'medium', 'high', 'critical']:
#         print("ERROR: wrong severity: %s" % severity)
#         severity = 'info'
#     ### check if project exists
#     try:
#         prj = Project.objects.get(id=projectid)
#     except Project.DoesNotExist:
#         return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})
#     ### get search parameters
#     if request.query_params:
#         if 'search[value]' in request.query_params:
#             search_value = request.query_params['search[value]']
#         else:
#             search_value = None
#     else:
#         search_value = None
#     ### create queryset
#     five_days = datetime.now() - timedelta(days=settings.RECENT_DAYS) # X days ago
#     recent_active_domains = prj.asset_set.all().filter(monitor=True, last_scan_time__gte=make_aware(five_days))
#     queryset = Finding.objects.filter(last_seen__gte=make_aware(five_days), domain__in=recent_active_domains, severity=severity)
#     ### filter by search value
#     if search_value and len(search_value)>1:
#         queryset = queryset.filter(
#             Q(vulnname__icontains=search_value)|
#             Q(description__icontains=search_value)
#         )
#     ### get variables
#     order_by_column, order_direction = get_ordering_vars(request.query_params,
#                                                          default_column='last_seen',
#                                                          default_direction='-')
#     ### order queryset
#     if order_by_column:
#         queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
#     kwrds = paginator.paginate_queryset(queryset, request)
#     serializer = FindingSerializer(instance=kwrds, many=True)
#     return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_all_findings(request, projectid, format=None):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()

    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    ### create queryset
    active_domains = prj.asset_set.all().filter(monitor=True)
    queryset = Finding.objects.filter(domain__in=active_domains)

    # Filter by monitored/ignored/all status if provided
    selection_param = request.query_params.get('selection', 'monitored')
    if selection_param == 'monitored':
        queryset = queryset.filter(ignore=False)
    elif selection_param == 'ignored':
        queryset = queryset.filter(ignore=True)
    # 'all' returns all, no filter

    # Filter by reported status if provided
    reported_param = request.query_params.get('reported', None)
    if reported_param is not None:
        if reported_param.lower() == 'reported':
            queryset = queryset.filter(last_reported__isnull=False)
        elif reported_param.lower() == 'not_reported':
            queryset = queryset.filter(last_reported__isnull=True)

    # Filter by severity if provided
    severity_param = request.query_params.get('severity', None)
    if severity_param is not None and severity_param != "":
        queryset = queryset.filter(severity__iexact=severity_param)

    # Get search parameters
    search_value = request.query_params.get('search[value]', None)
    queryset = apply_search_filter(
        queryset, search_value,
        ['name__icontains', 'description__icontains', 'source__icontains'],
        min_length=1
    )

    search_domain_name = request.query_params.get('columns[1][search][value]', None)
    search_name = request.query_params.get('columns[2][search][value]', None)
    search_type = request.query_params.get('columns[3][search][value]', None)
    search_description = request.query_params.get('columns[4][search][value]', None)
    search_source = request.query_params.get('columns[5][search][value]', None)
    search_severity = request.query_params.get('columns[6][search][value]', None)
    search_scan_date = request.query_params.get('columns[7][search][value]', None)
    search_last_reported = request.query_params.get('columns[8][search][value]', None)
    search_comment = request.query_params.get('columns[9][search][value]', None)

    ### filter by column-specific search values
    queryset = apply_column_search(queryset, search_domain_name, 'domain_name__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_name, 'name__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_type, 'type__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_description, 'description__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_source, 'source__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_severity, 'severity__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_scan_date, 'scan_date__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_last_reported, 'last_reported__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_comment, 'comment__icontains', min_length=1)

    ### get variables
    order_by_column, order_direction = get_ordering_vars(request.query_params,
                                                         default_column='severity',
                                                         default_direction='-')
    
    ### order queryset
    if order_by_column:
        if order_by_column == 'severity':
            # Custom ordering for severity: critical > high > medium > low > info > (empty/null)
            severity_order = Case(
                When(severity__iexact='critical', then=1),
                When(severity__iexact='high', then=2),
                When(severity__iexact='medium', then=3),
                When(severity__iexact='low', then=4),
                When(severity__iexact='info', then=5),
                default=6,
                output_field=IntegerField(),
            )
            if order_direction == '-':
                # Descending: critical first (ascending severity_order: 1, 2, 3...)
                queryset = queryset.annotate(severity_order=severity_order).order_by('severity_order', '-first_seen')
            else:
                # Ascending: info/unknown first (descending severity_order: 6, 5, 4...)
                queryset = queryset.annotate(severity_order=severity_order).order_by('-severity_order', '-first_seen')
        else:
            queryset = queryset.order_by('%s%s' % (order_direction, order_by_column))
    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_data_leaks(request, projectid, format=None):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()

    ### check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})


    # create queryset
    data_leak_sources = ["porch-pirate", "swaggerhub", "ai_scribd", "git-hound", "ransomlook"]
    keywords = prj.keyword_set.all()#.filter(enabled=True)
    queryset = Finding.objects.filter(source__in=data_leak_sources)

    # Filter by selection (monitored/ignored/all)
    selection_param = request.query_params.get('selection', 'monitored')
    if selection_param == 'monitored':
        queryset = queryset.filter(ignore=False)
    elif selection_param == 'ignored':
        queryset = queryset.filter(ignore=True)
    # 'all' returns all, no filter


    # Global search
    search_value = request.query_params.get('search[value]', None)
    queryset = apply_search_filter(
        queryset, search_value,
        ['domain_name__icontains', 'keyword__keyword__icontains', 'source__icontains',
         'name__icontains', 'description__icontains', 'url__icontains', 'scan_date__icontains'],
        min_length=1
    )

    # Column-specific search
    search_keyword = request.query_params.get('columns[1][search][value]', None)
    search_source = request.query_params.get('columns[2][search][value]', None)
    search_name = request.query_params.get('columns[3][search][value]', None)
    search_description = request.query_params.get('columns[4][search][value]', None)
    search_url = request.query_params.get('columns[5][search][value]', None)
    search_scan_date = request.query_params.get('columns[6][search][value]', None)
    search_comment = request.query_params.get('columns[7][search][value]', None)

    queryset = apply_column_search(queryset, search_keyword, 'keyword__keyword__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_source, 'source__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_name, 'name__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_description, 'description__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_url, 'url__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_scan_date, 'scan_date__icontains', min_length=1)
    queryset = apply_column_search(queryset, search_comment, 'comment__icontains', min_length=1)

    # Handle sorting
    order_column = request.query_params.get('order[0][column]', None)
    order_dir = request.query_params.get('order[0][dir]', 'asc')
    
    if order_column is not None:
        # Map DataTable column indices to model fields
        column_mapping = {
            '0': 'id',  # Operations column (not sortable, but included for completeness)
            '1': 'keyword__keyword',  # Keyword
            '2': 'source',  # Source
            '3': 'name',  # Name
            '4': 'description',  # Description
            '5': 'url',  # URL
            '6': 'scan_date',  # Scan Date
            '7': 'comment',  # Comment
        }
        
        sort_field = column_mapping.get(order_column)
        if sort_field:
            if order_dir == 'desc':
                sort_field = '-' + sort_field
            queryset = queryset.order_by(sort_field)
    else:
        # Default sorting by scan_date descending
        queryset = queryset.order_by('-scan_date')

    kwrds = paginator.paginate_queryset(queryset, request)
    serializer = FindingSerializer(instance=kwrds, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['DELETE'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def delete_finding(request, projectid, findingid):
    """Delete a specific finding by ID for a given project."""
    if not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    try:
        # Check if the project exists
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'message': 'Project does not exist', 'status': 'failure'}, status=404)

    try:
        # Check if the finding exists and belongs to the project
        finding = Finding.objects.get(id=findingid)
        finding.delete()
        return JsonResponse({'message': 'Finding successfully deleted', 'status': 'success'}, status=200)
    except Finding.DoesNotExist:
        return JsonResponse({'message': 'Finding does not exist', 'status': 'failure'}, status=404)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def update_finding_comment(request, projectid, findingid):
    """Update a finding's comment
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission to modify findings.")
    
    try:
        # Check if the project exists
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'message': 'Project does not exist', 'status': 'failure'}, status=404)
    
    try:
        finding = Finding.objects.get(id=findingid)
        comment = request.POST.get('comment', '')
        finding.comment = comment
        finding.save()
        return JsonResponse({'message': 'Comment updated successfully', 'comment': comment, 'status': 'success'}, status=200)
    except Finding.DoesNotExist:
        return JsonResponse({'message': 'Finding not found', 'status': 'failure'}, status=404)
    except Exception as e:
        return JsonResponse({'message': str(e), 'status': 'failure'}, status=500)
    
##### END FINDINGS ###########

##### JOBS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_jobs(request, projectid):
    if not request.user.has_perm('project.view_job'):
        return HttpResponseForbidden("You do not have permission to view this.")

    # check if project exists
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "status": True,
            "code": 200,
            "next": None,
            "previous": None,
            "count": 0,
            "iTotalRecords": 0,
            "iTotalDisplayRecords": 0,
            "results": []
        })

    queryset = Job.objects.filter(related_project=prj).order_by('-created_at')
    queryset = queryset.annotate(username=F('user__username'))

    paginator = CustomPaginator()
    jobs = paginator.paginate_queryset(queryset, request)
    serializer = JobSerializer(instance=jobs, many=True)
    data = serializer.data

    # Remove 'output' field from each job in the response
    for job_obj, job_instance in zip(data, jobs):
        job_obj['username'] = getattr(job_instance, 'username', None)
        if 'output' in job_obj:
            del job_obj['output']

    return paginator.get_paginated_response(data)

##### END JOBS ###############

@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_screenshots(request, projectid, format=None):
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission to view this project.")

    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({
            "draw": int(request.GET.get('draw', 1)),
            "recordsTotal": 0,
            "recordsFiltered": 0,
            "data": []
        })

    # Filtering and search
    domains = prj.asset_set.all().filter(monitor=True)
    queryset = Screenshot.objects.filter(domain__in=domains).order_by('-date')

    # DataTables search on columns
    search_url = request.GET.get('columns[0][search][value]', '')
    search_technologies = request.GET.get('columns[2][search][value]', '')
    search_title = request.GET.get('columns[3][search][value]', '')
    search_status_code = request.GET.get('columns[4][search][value]', '')
    search_webserver = request.GET.get('columns[5][search][value]', '')
    search_date = request.GET.get('columns[6][search][value]', '')
    
    queryset = apply_column_search(queryset, search_url, 'url__icontains')
    queryset = apply_column_search(queryset, search_technologies, 'technologies__icontains')
    queryset = apply_column_search(queryset, search_title, 'title__icontains')
    queryset = apply_column_search(queryset, search_status_code, 'status_code__icontains')
    queryset = apply_column_search(queryset, search_webserver, 'webserver__icontains')
    queryset = apply_column_search(queryset, search_date, 'date__icontains')

    # Global search
    search_value = request.GET.get('search[value]', '')
    queryset = apply_search_filter(
        queryset, search_value,
        ['url__icontains', 'technologies__icontains', 'title__icontains',
         'status_code__icontains', 'webserver__icontains']
    )

    # Ordering
    order_column_index = request.GET.get('order[0][column]', None)
    order_dir = request.GET.get('order[0][dir]', 'desc')
    order_columns = ['url', '', 'technologies', 'title', 'status_code', 'webserver', 'date']
    if order_column_index is not None:
        idx = int(order_column_index)
        if order_columns[idx]:
            order_field = order_columns[idx]
            if order_dir == 'desc':
                order_field = '-' + order_field
            queryset = queryset.order_by(order_field)

    # Pagination
    # start = int(request.GET.get('start', 0))
    # length = int(request.GET.get('length', 25))
    # total = queryset.count()
    # page = queryset[start:start+length]

    # data = []
    # for s in page:
    #     data.append({
    #         'url': s.url,
    #         'screenshot_base64': s.screenshot_base64,
    #         'technologies': s.technologies,
    #         'title': s.title,
    #         'status_code': s.status_code,
    #         'webserver': s.webserver,
    #         'date': s.date.strftime('%Y-%m-%d %H:%M:%S'),
    #     })

    # return JsonResponse({
    #     'draw': int(request.GET.get('draw', 1)),
    #     'recordsTotal': total,
    #     'recordsFiltered': total,
    #     'data': data,
    # })

    paginator = CustomPaginator()
    screenshots = paginator.paginate_queryset(queryset, request)
    serializer = ScreenshotSerializer(instance=screenshots, many=True)
    data = serializer.data

    return paginator.get_paginated_response(data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication,))
@permission_classes((IsAuthenticated,))
def list_scheduled_jobs(request):
    if not request.user.has_perm('project.view_job'):
        return HttpResponseForbidden("You do not have permission.")

    # Fetch all periodic tasks (scheduled jobs)
    scheduled_jobs = PeriodicTask.objects.all().select_related('interval', 'crontab', 'clocked')
    # Use CustomPaginator for DataTables server-side pagination
    paginator = CustomPaginator()
    jobs_page = paginator.paginate_queryset(scheduled_jobs, request)
    results = []
    for job in jobs_page:
        # Prepare schedule string
        if job.interval:
            schedule = str(job.interval)
        elif job.crontab:
            schedule = str(job.crontab)
        elif job.clocked:
            schedule = f"Once at {job.clocked.clocked_time}"
        else:
            schedule = "-"
        results.append({
            'name': job.name,
            'task': job.task,
            'schedule': schedule,
            'enabled': job.enabled,
            'last_run_at': job.last_run_at.isoformat() if job.last_run_at else '',
            'description': getattr(job, 'description', ''),
        })
    # Return paginated response for DataTables
    return paginator.get_paginated_response(results)
