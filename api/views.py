from datetime import datetime, timedelta

from django.shortcuts import render
from django.http import HttpResponseForbidden, JsonResponse, HttpResponse, HttpResponseRedirect
from django.db.models import Q, Prefetch, Count, F, Case, When, IntegerField, TextField
from django.db.models.functions import Cast
from django.conf import settings
from django.urls import reverse
from django.utils.html import escape
from django.utils.timezone import make_aware

from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from api.authentication import ShepherdTokenAuthentication
from rest_framework import serializers as drf_serializers

from drf_spectacular.utils import extend_schema, inline_serializer

from api.pagination import CustomPaginator
from api.serializer import JobSerializer, ProjectSerializer, KeywordSerializer, SuggestionSerializer, AssetSerializer, FindingSerializer, PortSerializer, ScreenshotSerializer, DNSRecordSerializer, EndpointSerializer
from api.schema import (
    DATATABLES_PARAMETERS,
    SELECTION_PARAMETER,
    StatusMessageSerializer,
    SuccessMessageSerializer,
    BulkActionSerializer,
)
from api.utils import get_ordering_vars, apply_search_filter, apply_column_search, apply_column_search_multi

from project.models import Project
from keywords.models import Keyword
from assets.models import Asset
from jobs.models import Job
from findings.models import DNSRecord
from findings.models import Finding, Port, Screenshot, Endpoint
from assets.utils import ignore_asset
from findings.utils import ignore_finding, report_finding_to_nucleus
from findings.services.scanning import filter_assets_for_project, run_scan_jobs, run_burp_scan
from keywords.services.discovery import run_discovery_jobs
from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule, ClockedSchedule

# Create your views here.

##### PROJECTS ###############

@extend_schema(
    methods=['GET'],
    tags=['Projects'],
    summary='List projects',
    description='DataTables-backed list of all projects.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: ProjectSerializer(many=True)},
)
@extend_schema(
    methods=['POST'],
    tags=['Projects'],
    summary='Create project',
    description='Create a new project.',
    request=ProjectSerializer,
    responses={200: StatusMessageSerializer},
)
@api_view(['GET', 'POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def projects(request, format=None):
    """List all projects (GET) or create a project (POST)
    """
    if request.method == 'POST':
        return create_project(request)

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


def create_project(request):
    """Create a project. Dispatched from `projects` on POST.
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

@extend_schema(
    tags=['Suggestions'],
    summary='List suggestions',
    description='DataTables-backed list of asset suggestions for a project.',
    parameters=DATATABLES_PARAMETERS + [SELECTION_PARAMETER],
    responses={200: SuggestionSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_suggestions(request, projectid, format=None):
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission to view this project.")

    selection = request.query_params.get('selection', 'visible')
    vtype = request.query_params.get('vtype', 'all')

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
    search_registrant_info = request.query_params.get('columns[12][search][value]', None)

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
    queryset = apply_column_search_multi(queryset, search_value, 'value__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_source, 'source__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_tag, 'tag__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_description, 'description__icontains', min_length=1)
    
    ### Don't use select_related as it causes performance issues with self-referencing FK
    queryset = apply_column_search_multi(queryset, search_redirect_to, 'redirects_to__value__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_creation_date, 'creation_time__icontains', min_length=1)
    
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

    # Registrant info filter: match if search text appears anywhere in the JSON values
    if search_registrant_info and search_registrant_info.strip():
        is_negative = search_registrant_info.startswith('!')
        term = search_registrant_info.lstrip('!').strip()
        if term:
            queryset = queryset.annotate(ri_text=Cast('registrant_info', TextField()))
            if is_negative:
                # Include NULLs (no registrant info) and rows that don't contain the term
                queryset = queryset.filter(Q(registrant_info__isnull=True) | ~Q(ri_text__icontains=term))
            else:
                queryset = queryset.filter(ri_text__icontains=term)

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


@extend_schema(
    tags=['Suggestions'],
    summary='Bulk update suggestions',
    description='Bulk actions on suggestions. POST body: action=monitor|ignore|move|delete, id[]=uuid... `move` reactivates an ignored suggestion.',
    request=BulkActionSerializer,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def bulk_suggestions(request, projectid, format=None):
    """Bulk actions on suggestions. POST body: action=monitor|ignore|move|delete, id[]=uuid...

    `move` reactivates an ignored suggestion.
    """
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    try:
        Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    action = request.POST.get('action')
    if not action:
        if 'btnmonitor' in request.POST:
            action = 'monitor'
        elif 'btnignore' in request.POST:
            action = 'ignore'
        elif 'btnmove' in request.POST:
            action = 'move'
        elif 'btndelete' in request.POST:
            action = 'delete'
    if action not in ('monitor', 'ignore', 'move', 'delete'):
        return JsonResponse({'success': False, 'error': 'Unknown action'}, status=400)
    if action in ('monitor', 'ignore', 'move') and not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    if action == 'delete' and not request.user.has_perm('assets.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    id_lst = request.POST.getlist('id[]')
    if not id_lst:
        return JsonResponse({'success': False, 'error': 'No items selected'}, status=400)
    errors = []
    for item in id_lst:
        try:
            s_obj = Asset.objects.get(uuid=item, scope='external')
            if action == 'delete':
                s_obj.delete()
            elif action == 'ignore':
                s_obj.ignore = True
                s_obj.save()
            elif action == 'move':
                s_obj.ignore = False
                s_obj.save()
            elif action == 'monitor':
                if s_obj.type in ['certificate', 'domain']:
                    try:
                        m_obj = Asset.objects.get(uuid=s_obj.uuid)
                    except Asset.DoesNotExist:
                        m_obj = Asset()
                        m_obj.related_keyword = s_obj.related_keyword
                        m_obj.related_project = s_obj.related_project
                        m_obj.value = s_obj.value
                        m_obj.uuid = s_obj.uuid
                        m_obj.source = s_obj.source
                        m_obj.creation_time = s_obj.creation_time
                        m_obj.description = s_obj.description
                        m_obj.link = s_obj.link
                        m_obj.save()
                    s_obj.monitor = True
                    s_obj.save()
                else:
                    errors.append('Unsupported type: %s' % s_obj.type)
        except Asset.DoesNotExist:
            errors.append('Unknown Suggestion: %s' % item)
        except Exception as e:
            errors.append(str(e))
    if errors:
        return JsonResponse({'success': False, 'error': '; '.join(errors[:5])}, status=400)
    return JsonResponse({'success': True, 'message': 'Action completed successfully'})


##### END SUGGESTIONS ###########


##### ASSETS ###############
@extend_schema(
    tags=['Assets'],
    summary='List assets',
    description='DataTables-backed list of assets for a project.',
    parameters=DATATABLES_PARAMETERS + [SELECTION_PARAMETER],
    responses={200: AssetSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_assets(request, projectid, format=None):
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission to view this project.")

    selection = request.query_params.get('selection', 'monitored')

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
        'registrant_info': request.query_params.get('columns[11][search][value]', None),
    }

    ### create queryset
    if selection in ['monitored']:
        queryset = prj.asset_set.filter(monitor=True, ignore=False)
    else:
        queryset = prj.asset_set.filter(monitor=False, ignore=False)

    # Annotate vulnerabilities (exclude ignored findings)
    queryset = queryset.annotate(
        vuln_info=Count('finding', filter=Q(finding__severity='info') & Q(finding__ignore=False)),
        vuln_critical=Count('finding', filter=Q(finding__severity='critical') & Q(finding__ignore=False)),
        vuln_high=Count('finding', filter=Q(finding__severity='high') & Q(finding__ignore=False)),
        vuln_medium=Count('finding', filter=Q(finding__severity='medium') & Q(finding__ignore=False)),
        vuln_low=Count('finding', filter=Q(finding__severity='low') & Q(finding__ignore=False))
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
    queryset = apply_column_search_multi(queryset, search_columns['value'], 'value__icontains')
    
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

    queryset = apply_column_search_multi(queryset, search_columns['tag'], 'tag__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_columns['source'], 'source__icontains')
    queryset = apply_column_search_multi(queryset, search_columns['description'], 'description__icontains')
    queryset = apply_column_search_multi(queryset, search_columns['last_scan_time'], 'last_scan_time__icontains')
    queryset = apply_column_search_multi(queryset, search_columns['creation_time'], 'creation_time__icontains')
    
    # IP search (can be IPv4 or IPv6)
    if search_columns['ip']:
        queryset = apply_search_filter(
            queryset, search_columns['ip'],
            ['ipv4__icontains', 'ipv6__icontains'],
            min_length=1
        )
    
    queryset = apply_column_search_multi(queryset, search_columns['owner'], 'owner__icontains', min_length=1)

    # Registrant info filter: match if search text appears anywhere in the JSON values
    if search_columns['registrant_info'] and search_columns['registrant_info'].strip():
        is_negative = search_columns['registrant_info'].startswith('!')
        term = search_columns['registrant_info'].lstrip('!').strip()
        if term:
            queryset = queryset.annotate(ri_text=Cast('registrant_info', TextField()))
            if is_negative:
                # Include NULLs (no registrant info) and rows that don't contain the term
                queryset = queryset.filter(Q(registrant_info__isnull=True) | ~Q(ri_text__icontains=term))
            else:
                queryset = queryset.filter(ri_text__icontains=term)

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


@extend_schema(
    tags=['Assets'],
    summary='Bulk update assets',
    description='Bulk actions on assets: ignore, move, delete. POST body: action=ignore|move|delete, id[]=uuid...',
    request=BulkActionSerializer,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def bulk_assets(request, projectid, format=None):
    """Bulk actions on assets: ignore, move, delete. POST body: action=ignore|move|delete, id[]=uuid..."""
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")
    if not request.user.has_perm('assets.change_asset'):
        return HttpResponseForbidden("You do not have permission.")
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    action = request.POST.get('action')
    if not action:
        if 'btnignore' in request.POST:
            action = 'ignore'
        elif 'btnmove' in request.POST:
            action = 'move'
        elif 'btndelete' in request.POST:
            action = 'delete'
    if action not in ('ignore', 'move', 'delete'):
        return JsonResponse({'success': False, 'error': 'Unknown action'}, status=400)
    if action == 'delete' and not request.user.has_perm('assets.delete_asset'):
        return HttpResponseForbidden("You do not have permission.")
    id_lst = request.POST.getlist('id[]')
    if not id_lst:
        return JsonResponse({'success': False, 'error': 'No items selected'}, status=400)
    errors = []
    for uuid in id_lst:
        try:
            if action == 'ignore':
                ignore_asset(uuid, prj)
            elif action == 'move':
                a_obj = Asset.objects.get(uuid=uuid)
                a_obj.monitor = False
                a_obj.save()
            elif action == 'delete':
                a_obj = Asset.objects.get(uuid=uuid)
                a_obj.delete()
        except Asset.DoesNotExist:
            errors.append('Unknown Asset: %s' % uuid)
        except Exception as e:
            errors.append(str(e))
    if errors:
        return JsonResponse({'success': False, 'error': '; '.join(errors[:5])}, status=400)
    return JsonResponse({'success': True, 'message': 'Action completed successfully'})


##### END ASSETS ###########

##### DNS RECORDS ###############

@extend_schema(
    tags=['Assets'],
    summary='List DNS records',
    description='DataTables-backed list of DNS records for a project.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: DNSRecordSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_dns_records(request, projectid, format=None):
    if not request.user.has_perm('assets.view_asset'):
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
    queryset = apply_column_search_multi(queryset, search_asset, 'related_asset__value__icontains', min_length=1)
    
    # Record type uses exact match (case-insensitive)
    if search_record_type:
        is_negative = search_record_type.startswith('!')
        record_type_value = search_record_type.lstrip('!')
        if len(record_type_value) > 0:
            if is_negative:
                queryset = queryset.exclude(record_type__iexact=record_type_value)
            else:
                queryset = queryset.filter(record_type__iexact=record_type_value)
    
    queryset = apply_column_search_multi(queryset, search_record_value, 'record_value__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_ttl, 'ttl__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_last_checked, 'last_checked__icontains', min_length=1)

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

@extend_schema(
    tags=['Assets'],
    summary='List endpoints',
    description='DataTables-backed list of web endpoints for a project.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: EndpointSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_endpoints(request, projectid, format=None):
    if not request.user.has_perm('assets.view_asset'):
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
    search_asset = request.query_params.get('columns[2][search][value]', None)
    search_url = request.query_params.get('columns[1][search][value]', None)
    search_technologies = request.query_params.get('columns[3][search][value]', None)
    search_date = request.query_params.get('columns[4][search][value]', None)

    ### create queryset - only for monitored assets
    queryset = Endpoint.objects.filter(
        asset__related_project=prj,
        asset__monitor=True,
        asset__ignore=False,
    ).select_related('asset')

    ### filter by search parameters
    queryset = apply_column_search_multi(queryset, search_asset, 'asset__value__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_url, 'url__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_technologies, 'technologies__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_date, 'date__icontains', min_length=1)

    ### get ordering variables
    order_by_column, order_direction = get_ordering_vars(
        request.query_params,
        default_column='date',
        default_direction='-'
    )
    
    ### map frontend column names to database field names
    if order_by_column == 'asset_value':
        order_by_column = 'asset__value'
    elif order_by_column == 'asset_uuid':
        order_by_column = 'asset__uuid'
    
    ### order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    endpoints = paginator.paginate_queryset(queryset, request)
    serializer = EndpointSerializer(instance=endpoints, many=True)
    return paginator.get_paginated_response(serializer.data)

##### END WEB ENDPOINTS ###########

##### KEYWORDS ###############

@extend_schema(
    tags=['Keywords'],
    summary='List keywords',
    description='DataTables-backed list of keywords for a project.',
    parameters=DATATABLES_PARAMETERS + [SELECTION_PARAMETER],
    responses={200: KeywordSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_keywords(request, projectid, format=None):
    if not request.user.has_perm('keywords.view_keyword'):
        return HttpResponseForbidden("You do not have permission to view this project.")

    selection = request.query_params.get('selection', 'all')

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


@extend_schema(
    tags=['Keywords'],
    summary='Add keywords',
    description='Add one or more keywords to a project by project name.',
    request=inline_serializer(
        name='AddKeywordRequest',
        fields={
            'projectname': drf_serializers.CharField(),
            'keywords': drf_serializers.JSONField(help_text='A single keyword string or a list of strings.'),
        },
    ),
    responses={200: StatusMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def add_keyword(request, format=None):
    """Add keywords to a project
    """
    return _add_keyword(request)


@extend_schema(
    deprecated=True,
    tags=['Keywords'],
    summary='Add keywords (deprecated alias)',
    description='Deprecated. Use POST /api/v1/keywords/add/ instead.',
    request=inline_serializer(
        name='AddKeywordLegacyRequest',
        fields={
            'projectname': drf_serializers.CharField(),
            'keywords': drf_serializers.JSONField(help_text='A single keyword string or a list of strings.'),
        },
    ),
    responses={200: StatusMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def add_keyword_legacy(request, format=None):
    """Deprecated alias of add_keyword."""
    return _add_keyword(request)


def _add_keyword(request):
    if not request.user.has_perm('keywords.add_keyword'):
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


@extend_schema(
    tags=['Keywords'],
    summary='Bulk sync keywords',
    description='Sync the full keyword set of a project: create, update and delete in one call.',
    request=inline_serializer(
        name='BulkUpdateKeywordsRequest',
        fields={
            'keywords': drf_serializers.ListField(
                child=drf_serializers.DictField(),
                help_text='Items with optional id plus keyword, ktype, description, enabled.',
            ),
        },
    ),
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def bulk_update_keywords(request, projectid, format=None):
    """Sync the full keyword set of a project: create, update and delete in one call
    """
    if not request.user.has_perm('keywords.add_keyword'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        project = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Project not found.'}, status=400)

    keywords_data = request.data.get('keywords', [])

    # Get existing keyword IDs for this project
    existing_ids = set(
        Keyword.objects.filter(related_project=project).values_list('id', flat=True)
    )

    # Track which IDs we're keeping
    submitted_ids = set()

    for kw_data in keywords_data:
        kw_id = kw_data.get('id')
        keyword_value = escape(kw_data.get('keyword', '').strip())
        ktype = kw_data.get('ktype', 'registrant_org')
        description = escape(kw_data.get('description', '').strip())
        enabled = kw_data.get('enabled', True)

        if not keyword_value:
            continue

        if kw_id:
            # Update existing keyword
            submitted_ids.add(kw_id)
            try:
                kw = Keyword.objects.get(id=kw_id, related_project=project)
                kw.keyword = keyword_value
                kw.ktype = ktype
                kw.description = description
                kw.enabled = enabled
                kw.save()
            except Keyword.DoesNotExist:
                # ID doesn't exist, create new
                Keyword.objects.create(
                    related_project=project,
                    keyword=keyword_value,
                    ktype=ktype,
                    description=description,
                    enabled=enabled
                )
        else:
            # Create new keyword
            Keyword.objects.create(
                related_project=project,
                keyword=keyword_value,
                ktype=ktype,
                description=description,
                enabled=enabled
            )

    # Delete keywords that were removed (IDs in existing but not in submitted)
    ids_to_delete = existing_ids - submitted_ids
    if ids_to_delete:
        Keyword.objects.filter(id__in=ids_to_delete, related_project=project).delete()

    return JsonResponse({
        'success': True,
        'message': 'Keywords updated successfully.'
    })


##### END KEYWORDS ###############

##### PORTS ###############
@extend_schema(
    tags=['Ports'],
    summary='List ports',
    description='DataTables-backed list of ports for a project.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: PortSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_ports(request, projectid, format=None):
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission to view this project.")
    
    paginator = CustomPaginator()
    try:
        prj = Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({"status": True, "code": 200, "next": None, "previous": None, "count": 0, "iTotalRecords": 0, "iTotalDisplayRecords": 0, "results": []})

    # Fetch all active domains associated with the project (exclude ignored assets)
    active_domains = Asset.objects.filter(related_project=prj, monitor=True, ignore=False)

    # Define queryset to filter ports by active domains
    queryset = Port.objects.filter(asset__in=active_domains)

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
    queryset = apply_column_search_multi(queryset, search_domain_name, 'asset_name__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_port, 'port__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_banner, 'banner__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_cpe, 'cpe__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_last_scan, 'scan_date__icontains', min_length=1)

    # Get ordering variables
    order_by_column, order_direction = get_ordering_vars(request.query_params, default_column='scan_date', default_direction='-')

    # Order queryset
    if order_by_column:
        queryset = queryset.order_by(f'{order_direction}{order_by_column}')

    # Paginate queryset
    ports = paginator.paginate_queryset(queryset, request)
    serializer = PortSerializer(instance=ports, many=True)

    return paginator.get_paginated_response(serializer.data)

@extend_schema(
    tags=['Ports'],
    summary='Delete port',
    description='Delete a single port by ID.',
    responses={200: SuccessMessageSerializer},
)
@api_view(['DELETE'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def delete_port(request, projectid, portid):
    if not request.user.has_perm('findings.delete_port'):
        return HttpResponseForbidden("You do not have permission to delete ports.")

    try:
        Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'error': 'Project not found'}, status=404)

    try:
        port_obj = Port.objects.get(id=portid, asset__related_project__id=projectid)
    except Port.DoesNotExist:
        return JsonResponse({'error': 'Port not found'}, status=404)

    port_obj.delete()
    return JsonResponse({'success': True})


@extend_schema(
    tags=['Ports'],
    summary='Bulk delete ports',
    description='Bulk delete ports. POST body: action=delete, id[]=id...',
    request=BulkActionSerializer,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def bulk_ports(request, projectid, format=None):
    """Bulk delete ports. POST body: action=delete, id[]=id..."""
    if not request.user.has_perm('findings.view_port'):
        return HttpResponseForbidden("You do not have permission.")
    if not request.user.has_perm('findings.delete_port'):
        return HttpResponseForbidden("You do not have permission.")
    try:
        Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    action = request.POST.get('action')
    if not action and 'btndelete' in request.POST:
        action = 'delete'
    if action != 'delete':
        return JsonResponse({'success': False, 'error': 'Unknown action'}, status=400)
    port_ids = request.POST.getlist('id[]')
    if not port_ids:
        return JsonResponse({'success': False, 'error': 'No items selected'}, status=400)
    port_objs = Port.objects.filter(id__in=port_ids, asset__related_project__id=projectid)
    count = port_objs.count()
    port_objs.delete()
    return JsonResponse({'success': True, 'message': 'Deleted %s port(s)' % count})


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
#     queryset = Finding.objects.filter(last_seen__gte=make_aware(five_days), asset__in=recent_active_domains, severity=severity)
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


@extend_schema(
    tags=['Findings'],
    summary='List findings',
    description='DataTables-backed list of security findings for a project.',
    parameters=DATATABLES_PARAMETERS + [SELECTION_PARAMETER],
    responses={200: FindingSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
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
    active_domains = prj.asset_set.all().filter(monitor=True, ignore=False)
    queryset = Finding.objects.filter(asset__in=active_domains)

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
    queryset = apply_column_search_multi(queryset, search_domain_name, 'asset_name__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_name, 'name__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_type, 'type__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_description, 'description__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_source, 'source__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_severity, 'severity__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_scan_date, 'scan_date__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_last_reported, 'last_reported__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_comment, 'comment__icontains', min_length=1)

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

@extend_schema(
    tags=['Data Leaks'],
    summary='List data leaks',
    description='DataTables-backed list of data-leak findings for a project.',
    parameters=DATATABLES_PARAMETERS + [SELECTION_PARAMETER],
    responses={200: FindingSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
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
    data_leak_sources = ["porch-pirate", "swaggerhub", "ai_scribd", "git-hound", "ghleaks", "ransomlook"]
    # Only include findings whose keyword belongs to the currently selected project
    queryset = Finding.objects.filter(
        source__in=data_leak_sources,
        keyword__related_project_id=projectid,
    )

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
        ['asset_name__icontains', 'keyword__keyword__icontains', 'source__icontains',
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

    queryset = apply_column_search_multi(queryset, search_keyword, 'keyword__keyword__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_source, 'source__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_name, 'name__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_description, 'description__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_url, 'url__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_scan_date, 'scan_date__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_comment, 'comment__icontains', min_length=1)

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

@extend_schema(
    tags=['Findings'],
    summary='Delete finding',
    description='Delete a specific finding by ID for a given project.',
    responses={200: StatusMessageSerializer},
)
@api_view(['DELETE'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
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


@extend_schema(
    tags=['Findings'],
    summary='Bulk update findings',
    description='Bulk actions on findings: ignore, delete, report. POST body: action=ignore|delete|report, id[]=id...',
    request=BulkActionSerializer,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def bulk_findings(request, projectid, format=None):
    """Bulk actions on findings: ignore, delete, report. POST body: action=ignore|delete|report, id[]=id..."""
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    try:
        Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    action = request.POST.get('action')
    if not action:
        if 'btnignore' in request.POST:
            action = 'ignore'
        elif 'btndelete' in request.POST:
            action = 'delete'
        elif 'btnreport' in request.POST:
            action = 'report'
    if action not in ('ignore', 'delete', 'report'):
        return JsonResponse({'success': False, 'error': 'Unknown action'}, status=400)
    if action in ('ignore', 'report') and not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission.")
    if action == 'delete' and not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission.")
    id_lst = request.POST.getlist('id[]')
    if not id_lst:
        return JsonResponse({'success': False, 'error': 'No items selected'}, status=400)
    errors = []
    for findingid in id_lst:
        try:
            if action == 'delete':
                Finding.objects.get(id=findingid).delete()
            elif action == 'ignore':
                ignore_finding(findingid)
            elif action == 'report':
                report_finding_to_nucleus(findingid)
        except Finding.DoesNotExist:
            errors.append('Unknown Finding: %s' % findingid)
        except Exception as e:
            errors.append(str(e))
    if errors:
        return JsonResponse({'success': False, 'error': '; '.join(errors[:5])}, status=400)
    return JsonResponse({'success': True, 'message': 'Action completed successfully'})


@extend_schema(
    tags=['Data Leaks'],
    summary='Bulk update data leaks',
    description='Bulk actions on data leak findings: ignore, delete. POST body: action=ignore|delete, id[]=id...',
    request=BulkActionSerializer,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def bulk_findings_data_leaks(request, projectid, format=None):
    """Bulk actions on data leak findings: ignore, delete. POST body: action=ignore|delete, id[]=id..."""
    if not request.user.has_perm('findings.view_finding'):
        return HttpResponseForbidden("You do not have permission.")
    try:
        Project.objects.get(id=projectid)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    action = request.POST.get('action')
    if not action:
        if 'btnignore' in request.POST:
            action = 'ignore'
        elif 'btndelete' in request.POST:
            action = 'delete'
    if action not in ('ignore', 'delete'):
        return JsonResponse({'success': False, 'error': 'Unknown action'}, status=400)
    if action == 'ignore' and not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission.")
    if action == 'delete' and not request.user.has_perm('findings.delete_finding'):
        return HttpResponseForbidden("You do not have permission.")
    id_lst = request.POST.getlist('id[]')
    if not id_lst:
        return JsonResponse({'success': False, 'error': 'No items selected'}, status=400)
    errors = []
    for findingid in id_lst:
        try:
            # Only act on findings whose keyword belongs to the current project
            finding = Finding.objects.get(id=findingid, keyword__related_project_id=projectid)
            if action == 'delete':
                finding.delete()
            elif action == 'ignore':
                ignore_finding(findingid)
        except Finding.DoesNotExist:
            errors.append('Unknown Finding: %s' % findingid)
        except Exception as e:
            errors.append(str(e))
    if errors:
        return JsonResponse({'success': False, 'error': '; '.join(errors[:5])}, status=400)
    return JsonResponse({'success': True, 'message': 'Action completed successfully'})


@extend_schema(
    tags=['Findings'],
    summary='Toggle finding ignore',
    description='Toggle the ignore status of a single finding.',
    request=None,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def toggle_finding_ignore(request, projectid, findingid):
    """Toggle the ignore status of a single finding
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission to modify findings.")

    try:
        ignore_finding(findingid)
        return JsonResponse({'success': True, 'message': 'Ignore status toggled successfully.'})
    except Finding.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Unknown Finding: %s' % findingid}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@extend_schema(
    tags=['Findings'],
    summary='Report finding to Nucleus',
    description='Send the details of a single finding to Nucleus.',
    request=None,
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def report_finding(request, projectid, findingid):
    """Send the details of a single finding to Nucleus
    """
    if not request.user.has_perm('findings.change_finding'):
        return HttpResponseForbidden("You do not have permission.")

    try:
        report_finding_to_nucleus(findingid)
    except Finding.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Unknown Finding: %s' % findingid}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

    return JsonResponse({'success': True, 'message': 'Finding sent to Nucleus successfully.'})


@extend_schema(
    tags=['Findings'],
    summary='Update finding comment',
    description="Update a finding's comment.",
    request=inline_serializer(
        name='UpdateFindingCommentRequest',
        fields={
            'comment': drf_serializers.CharField(allow_blank=True),
        },
    ),
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
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

@extend_schema(
    tags=['Jobs'],
    summary='List jobs',
    description='DataTables-backed list of jobs for a project.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: JobSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_jobs(request, projectid, format=None):
    if not request.user.has_perm('jobs.view_job'):
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

@extend_schema(
    tags=['Assets'],
    summary='List screenshots',
    description='DataTables-backed list of screenshots for a project.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: ScreenshotSerializer(many=True)},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
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

    # Filtering and search: only monitored assets that are not ignored
    domains = prj.asset_set.all().filter(monitor=True, ignore=False)
    queryset = Screenshot.objects.filter(asset__in=domains).order_by('-date')

    # DataTables search on columns
    search_url = request.GET.get('columns[0][search][value]', '')
    search_technologies = request.GET.get('columns[2][search][value]', '')
    search_title = request.GET.get('columns[3][search][value]', '')
    search_status_code = request.GET.get('columns[4][search][value]', '')
    search_webserver = request.GET.get('columns[5][search][value]', '')
    search_date = request.GET.get('columns[6][search][value]', '')
    search_asset_source = request.GET.get('columns[7][search][value]', '')
    
    queryset = apply_column_search_multi(queryset, search_url, 'url__icontains')
    queryset = apply_column_search_multi(queryset, search_technologies, 'technologies__icontains')
    queryset = apply_column_search_multi(queryset, search_title, 'title__icontains')
    queryset = apply_column_search_multi(queryset, search_status_code, 'status_code__icontains')
    queryset = apply_column_search_multi(queryset, search_webserver, 'webserver__icontains')
    queryset = apply_column_search_multi(queryset, search_date, 'date__icontains')
    queryset = apply_column_search_multi(queryset, search_asset_source, 'asset__source__icontains')

    # Global search
    search_value = request.GET.get('search[value]', '')
    queryset = apply_search_filter(
        queryset, search_value,
        ['url__icontains', 'technologies__icontains', 'title__icontains',
         'status_code__icontains', 'webserver__icontains', 'asset__source__icontains']
    )

    # Ordering
    order_column_index = request.GET.get('order[0][column]', None)
    order_dir = request.GET.get('order[0][dir]', 'desc')
    order_columns = ['url', '', 'technologies', 'title', 'status_code', 'webserver', 'date', 'asset__source']
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

@extend_schema(
    tags=['Jobs'],
    summary='List scheduled jobs',
    description='DataTables-backed list of Celery Beat scheduled jobs.',
    parameters=DATATABLES_PARAMETERS,
    responses={200: inline_serializer(
        name='ScheduledJob',
        fields={
            'name': drf_serializers.CharField(),
            'task': drf_serializers.CharField(),
            'schedule': drf_serializers.CharField(),
            'enabled': drf_serializers.BooleanField(),
            'last_run_at': drf_serializers.CharField(allow_blank=True),
            'description': drf_serializers.CharField(allow_blank=True),
        },
        many=True,
    )},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def list_scheduled_jobs(request):
    if not request.user.has_perm('jobs.view_job'):
        return HttpResponseForbidden("You do not have permission.")

    # Fetch all periodic tasks (scheduled jobs)
    queryset = PeriodicTask.objects.all().select_related('interval', 'crontab', 'clocked')

    # Column-specific search (DataTables columns 0-5: name, task, schedule, enabled, last_run_at, description)
    search_name = request.query_params.get('columns[0][search][value]', None)
    search_task = request.query_params.get('columns[1][search][value]', None)
    search_schedule = request.query_params.get('columns[2][search][value]', None)
    search_enabled = request.query_params.get('columns[3][search][value]', None)
    search_last_run_at = request.query_params.get('columns[4][search][value]', None)
    search_description = request.query_params.get('columns[5][search][value]', None)

    queryset = apply_column_search_multi(queryset, search_name, 'name__icontains', min_length=1)
    queryset = apply_column_search_multi(queryset, search_task, 'task__icontains', min_length=1)

    # Schedule is computed from interval/crontab/clocked; filter by interval period (e.g. "minutes") or crontab presence
    if search_schedule and len(search_schedule.strip()) >= 1:
        is_negative = search_schedule.startswith('!')
        schedule_value = search_schedule.strip().lstrip('!').lower()
        if schedule_value:
            schedule_q = Q(interval__period__icontains=schedule_value)
            if is_negative:
                queryset = queryset.exclude(schedule_q)
            else:
                queryset = queryset.filter(schedule_q)

    # Enabled: exact boolean match
    if search_enabled and search_enabled.strip().lower() in ('true', 'false'):
        queryset = queryset.filter(enabled=(search_enabled.strip().lower() == 'true'))

    # Last run: filter by year when 4 digits
    if search_last_run_at and len(search_last_run_at.strip()) >= 1:
        last_run_val = search_last_run_at.strip()
        if len(last_run_val) == 4 and last_run_val.isdigit():
            queryset = queryset.filter(last_run_at__year=int(last_run_val))

    if hasattr(PeriodicTask, 'description'):
        queryset = apply_column_search_multi(queryset, search_description, 'description__icontains', min_length=1)

    # Ordering: use get_ordering_vars (reads columns[order[0][column]][data])
    order_by_column, order_direction = get_ordering_vars(
        request.query_params,
        default_column='name',
        default_direction=''
    )
    # Map frontend column names to DB fields (schedule is computed, sort by last_run_at)
    if order_by_column == 'schedule':
        order_by_column = 'last_run_at'
    if order_by_column and order_by_column in ('name', 'task', 'enabled', 'last_run_at', 'description'):
        sort_field = order_direction + order_by_column
        queryset = queryset.order_by(sort_field)

    paginator = CustomPaginator()
    jobs_page = paginator.paginate_queryset(queryset, request)
    results = []
    for job in jobs_page:
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
    return paginator.get_paginated_response(results)


##### ASSET SCANS ###############

@extend_schema(
    tags=['Scans'],
    summary='Preview scan assets',
    description='Preview which assets match the control center filters.',
    responses={200: inline_serializer(
        name='ScansPreviewResponse',
        fields={
            'count': drf_serializers.IntegerField(),
            'sample': drf_serializers.ListField(child=drf_serializers.DictField()),
        },
    )},
)
@api_view(['GET'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def scans_preview(request, projectid, format=None):
    """Preview which assets match the control center filters
    """
    if not request.user.has_perm('assets.view_asset'):
        return HttpResponseForbidden("You do not have permission.")

    sources = request.query_params.getlist('sources[]') or request.query_params.getlist('sources')
    filters = {
        'type': request.query_params.get('type'),
        'scope': request.query_params.get('scope'),
        'sources': sources,
        'name': request.query_params.get('name'),
    }
    queryset = filter_assets_for_project(projectid, filters)
    new_assets_only = request.query_params.get('new_assets_only')
    if new_assets_only:
        queryset = queryset.filter(last_scan_time__isnull=True)
    count = queryset.count()
    sample = list(
        queryset.values('uuid', 'value', 'type', 'scope', 'source')[:25]
    )
    return JsonResponse({'count': count, 'sample': sample})


@extend_schema(
    tags=['Scans'],
    summary='Preselect scan assets',
    description='Store selected asset UUIDs in the session and hand back the control center URL.',
    request=inline_serializer(
        name='ScansPreselectRequest',
        fields={
            'uuids': drf_serializers.ListField(child=drf_serializers.CharField()),
        },
    ),
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def scans_preselect(request, projectid, format=None):
    """Store selected asset UUIDs in the session and hand back the control center URL
    """
    if not request.user.has_perm('findings.add_finding'):
        return HttpResponseForbidden("You do not have permission.")

    selected_uuids = request.data.get('uuids', [])
    if not selected_uuids:
        return JsonResponse({'success': False, 'message': 'No assets selected.'}, status=400)

    request.session['scan_selected_uuids'] = [str(u) for u in selected_uuids]
    return JsonResponse({'success': True, 'redirect': reverse('findings:control_center')})


@extend_schema(
    tags=['Scans'],
    summary='Launch scans',
    description='Launch the selected scanners against the requested set of assets.',
    request=inline_serializer(
        name='ScansLaunchRequest',
        fields={
            'filters': drf_serializers.DictField(required=False),
            'scans': drf_serializers.DictField(required=False),
            'asset_mode': drf_serializers.CharField(required=False),
            'selected_uuids': drf_serializers.ListField(
                child=drf_serializers.CharField(), required=False
            ),
        },
    ),
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def scans_launch(request, projectid, format=None):
    """Launch the selected scanners against the requested set of assets
    """
    if not request.user.has_perm('findings.add_finding'):
        return HttpResponseForbidden("You do not have permission.")

    filters = request.data.get('filters', {})
    scans = request.data.get('scans', {})
    asset_mode = request.data.get('asset_mode', 'all')

    scan_new_assets = False
    if asset_mode == 'all':
        asset_ids = []
        asset_count_display = Asset.objects.filter(related_project_id=projectid, monitor=True).count()
    elif asset_mode == 'new':
        asset_ids = []
        scan_new_assets = True
        asset_count_display = Asset.objects.filter(
            related_project_id=projectid, monitor=True, last_scan_time__isnull=True
        ).count()
    elif asset_mode == 'selected':
        asset_ids = request.data.get('selected_uuids', [])
        if not asset_ids:
            return JsonResponse({'success': False, 'message': 'No pre-selected assets.'}, status=400)
        asset_count_display = len(asset_ids)
    else:
        # "filter" mode: resolve UUIDs via filters
        queryset = filter_assets_for_project(projectid, filters)
        asset_ids = list(queryset.values_list('uuid', flat=True))
        if not asset_ids:
            return JsonResponse({'success': False, 'message': 'No assets match the filters.'}, status=400)
        asset_count_display = len(asset_ids)

    scan_flags = {
        'scan_nmap': bool(scans.get('scan_nmap')),
        'scan_httpx': bool(scans.get('scan_httpx')),
        'scan_playwright': bool(scans.get('scan_playwright')),
        'scan_katana': bool(scans.get('scan_katana')),
        'scan_shepherdai': bool(scans.get('scan_shepherdai')),
        'scan_nuclei': bool(scans.get('scan_nuclei')),
        'scan_nuclei_new_templates': bool(scans.get('scan_nuclei_new_templates')),
        'scan_domaintools': bool(scans.get('scan_domaintools')),
    }

    if not any(scan_flags.values()):
        return JsonResponse({'success': False, 'message': 'Select at least one scanner.'}, status=400)

    triggered = run_scan_jobs(projectid, request.user, asset_ids, scan_new_assets, scan_flags)
    return JsonResponse({
        'success': True,
        'asset_count': asset_count_display,
        'messages': triggered,
    })


@extend_schema(
    tags=['Scans'],
    summary='Launch Burp scan',
    description='Trigger a Burp Suite scan against selected web endpoint URLs.',
    request=inline_serializer(
        name='ScansBurpRequest',
        fields={
            'urls': drf_serializers.ListField(child=drf_serializers.CharField()),
        },
    ),
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def scans_burp(request, projectid, format=None):
    """Trigger a Burp Suite scan against selected web endpoint URLs
    """
    if not request.user.has_perm('findings.add_finding'):
        return JsonResponse({'success': False, 'message': 'Permission denied.'}, status=403)

    urls = request.data.get('urls', [])
    if not urls:
        return JsonResponse({'success': False, 'message': 'No URLs selected.'}, status=400)

    try:
        run_burp_scan(projectid, request.user, urls)
    except Exception:
        return JsonResponse({'success': False, 'message': 'Failed to prepare scan.'}, status=500)

    return JsonResponse({
        'success': True,
        'message': f'Burp Suite scan triggered for {len(urls)} URL(s). Check Jobs for progress.',
    })

##### END ASSET SCANS ###########

##### KEYWORD DISCOVERY ###############

@extend_schema(
    tags=['Discovery'],
    summary='Launch discovery',
    description='Launch keyword-based discovery scans from the discovery control center.',
    request=inline_serializer(
        name='DiscoveryLaunchRequest',
        fields={
            'keywords': drf_serializers.ListField(
                child=drf_serializers.IntegerField(),
                required=False,
                help_text='Keyword IDs; empty means all.',
            ),
            'scans': drf_serializers.DictField(required=False),
            'auto_monitor': drf_serializers.BooleanField(required=False),
            'post_actions': drf_serializers.DictField(required=False),
        },
    ),
    responses={200: SuccessMessageSerializer},
)
@api_view(['POST'])
@authentication_classes((SessionAuthentication, ShepherdTokenAuthentication))
@permission_classes((IsAuthenticated,))
def discovery_launch(request, projectid, format=None):
    """Launch keyword based discovery scans from the discovery control center
    """
    if not request.user.has_perm('assets.add_asset'):
        return HttpResponseForbidden("You do not have permission.")

    keyword_ids = request.data.get('keywords', [])  # Empty means all
    scans = request.data.get('scans', {})
    auto_monitor = request.data.get('auto_monitor', False)
    post_actions = request.data.get('post_actions', {})

    triggered_messages, launched = run_discovery_jobs(
        projectid, request.user, keyword_ids, scans, auto_monitor, post_actions
    )
    if not launched:
        return JsonResponse({'success': False, 'message': 'Select at least one scan or action.'}, status=400)

    return JsonResponse({
        'success': True,
        'messages': triggered_messages,
    })

##### END KEYWORD DISCOVERY ###########
