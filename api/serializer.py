
from rest_framework import serializers

from project.models import Job, Project, Keyword, Asset, DNSRecord
from findings.models import Finding, Port, Screenshot, Endpoint

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = '__all__'

class KeywordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Keyword
        fields = '__all__'

def _format_registrant_info_display(registrant_info):
    """Format registrant_info JSON into a short readable string for table display."""
    if not registrant_info or not isinstance(registrant_info, dict):
        return ''
    parts = []
    if registrant_info.get('registrant_org'):
        parts.append('Org: ' + str(registrant_info['registrant_org'])[:40])
    if registrant_info.get('registrant_name'):
        parts.append('Name: ' + str(registrant_info['registrant_name'])[:30])
    if registrant_info.get('registrant') and not parts:
        parts.append(str(registrant_info['registrant'])[:50])
    if registrant_info.get('registrar') and len(parts) < 2:
        parts.append('Registrar: ' + str(registrant_info['registrar'])[:25])
    return ' • '.join(parts) if parts else '—'


class SuggestionSerializer(serializers.ModelSerializer):
    ip = serializers.SerializerMethodField()
    registrant_info_display = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = '__all__'

    def get_registrant_info_display(self, obj):
        return _format_registrant_info_display(obj.registrant_info)

    def get_ip(self, obj):
        ips = []
        if obj.ipv4:
            ips.append(obj.ipv4)
        if obj.ipv6:
            ips.append(obj.ipv6)
        return ', '.join(ips) if ips else ''

class PortSerializer(serializers.ModelSerializer):
    asset_uuid = serializers.SerializerMethodField()

    class Meta:
        model = Port
        fields = '__all__'

    def get_asset_uuid(self, obj):
        return obj.asset.uuid if obj.asset else None

class AssetSerializer(serializers.ModelSerializer):
    vuln_critical = serializers.IntegerField()
    vuln_high = serializers.IntegerField()
    vuln_medium = serializers.IntegerField()
    vuln_low = serializers.IntegerField()
    vuln_info = serializers.IntegerField()
    vulns = serializers.SerializerMethodField()
    ip = serializers.SerializerMethodField()
    registrant_info_display = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = '__all__'

    def get_registrant_info_display(self, obj):
        return _format_registrant_info_display(obj.registrant_info)

    def get_vulns(self, obj):
        return '<span class="label label-default">'+str(obj.vuln_critical)+'</span><span class="label label-danger">'+str(obj.vuln_high)+'</span><span class="label label-warning">'+str(obj.vuln_medium)+'</span><span class="label label-success">'+str(obj.vuln_low)+'</span><span  class="label label-primary">'+str(obj.vuln_info)+'</span>'

    def get_ip(self, obj):
        ips = []
        if obj.ipv4:
            ips.append(obj.ipv4)
        if obj.ipv6:
            ips.append(obj.ipv6)
        return ', '.join(ips) if ips else ''

class FindingSerializer(serializers.ModelSerializer):
    keyword = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = '__all__'

    def get_keyword(self, obj):
        if obj.keyword:
            return obj.keyword.keyword
        return None

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'

class ScreenshotSerializer(serializers.ModelSerializer):
    asset_source = serializers.SerializerMethodField()

    class Meta:
        model = Screenshot
        fields = '__all__'

    def get_asset_source(self, obj):
        return obj.asset.source if obj.asset else ''

class DNSRecordSerializer(serializers.ModelSerializer):
    asset_value = serializers.SerializerMethodField()
    asset_uuid = serializers.SerializerMethodField()
    
    class Meta:
        model = DNSRecord
        fields = '__all__'
    
    def get_asset_value(self, obj):
        return obj.related_asset.value
    
    def get_asset_uuid(self, obj):
        return obj.related_asset.uuid

class EndpointSerializer(serializers.ModelSerializer):
    asset_value = serializers.SerializerMethodField()
    asset_uuid = serializers.SerializerMethodField()
    
    class Meta:
        model = Endpoint
        fields = '__all__'
    
    def get_asset_value(self, obj):
        return obj.asset.value if obj.asset else None
    
    def get_asset_uuid(self, obj):
        return obj.asset.uuid if obj.asset else None
        