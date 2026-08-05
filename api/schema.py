"""Reusable OpenAPI helpers for Shepherd's DataTables-backed API."""

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, inline_serializer
from rest_framework import serializers

DATATABLES_PARAMETERS = [
    OpenApiParameter(
        name='search[value]',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Global DataTables search string.',
        required=False,
    ),
    OpenApiParameter(
        name='order[0][column]',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Zero-based column index to sort by.',
        required=False,
    ),
    OpenApiParameter(
        name='order[0][dir]',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description="Sort direction: 'asc' or 'desc'.",
        required=False,
        enum=['asc', 'desc'],
    ),
    OpenApiParameter(
        name='start',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Pagination offset (DataTables start).',
        required=False,
    ),
    OpenApiParameter(
        name='length',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Page size (DataTables length).',
        required=False,
    ),
    OpenApiParameter(
        name='draw',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='DataTables draw counter (echoed in the response).',
        required=False,
    ),
]

SELECTION_PARAMETER = OpenApiParameter(
    name='selection',
    type=OpenApiTypes.STR,
    location=OpenApiParameter.QUERY,
    description='List filter mode used by the UI (e.g. monitored, ignored, all, visible).',
    required=False,
)

StatusMessageSerializer = inline_serializer(
    name='StatusMessage',
    fields={
        'message': serializers.CharField(),
        'status': serializers.CharField(),
    },
)

SuccessMessageSerializer = inline_serializer(
    name='SuccessMessage',
    fields={
        'success': serializers.BooleanField(),
        'message': serializers.CharField(required=False),
        'error': serializers.CharField(required=False),
    },
)

BulkActionSerializer = inline_serializer(
    name='BulkAction',
    fields={
        'action': serializers.CharField(help_text='Action to apply to the selected IDs.'),
        'id[]': serializers.ListField(
            child=serializers.CharField(),
            help_text='Selected item IDs / UUIDs.',
        ),
    },
)
