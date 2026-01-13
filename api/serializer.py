
from rest_framework import serializers

from project.models import Job, Project, Keyword, Asset, DNSRecord
from findings.models import Finding, Port, Screenshot

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = '__all__'

class KeywordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Keyword
        fields = '__all__'

class SuggestionSerializer(serializers.ModelSerializer):
    ip = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = '__all__'

    def get_ip(self, obj):
        ips = []
        if obj.ipv4:
            ips.append(obj.ipv4)
        if obj.ipv6:
            ips.append(obj.ipv6)
        return ', '.join(ips) if ips else ''

class PortSerializer(serializers.ModelSerializer):
    domain_uuid = serializers.SerializerMethodField()

    class Meta:
        model = Port
        fields = '__all__'

    def get_domain_uuid(self, obj):
        return obj.domain.uuid if obj.domain else None

class AssetSerializer(serializers.ModelSerializer):
    vuln_critical = serializers.IntegerField()
    vuln_high = serializers.IntegerField()
    vuln_medium = serializers.IntegerField()
    vuln_low = serializers.IntegerField()
    vuln_info = serializers.IntegerField()
    vulns = serializers.SerializerMethodField()
    ip = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = '__all__'

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
    asset = serializers.SerializerMethodField()
    keyword = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = '__all__'

    def get_asset(self, obj):
        if obj.domain:
            return obj.domain.value
        return None

    def get_keyword(self, obj):
        if obj.keyword:
            return obj.keyword.keyword
        return None

class JobSerializer(serializers.ModelSerializer):
    class Meta:
        model = Job
        fields = '__all__'

class ScreenshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = Screenshot
        fields = '__all__'

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
        