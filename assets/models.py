from django.db import models


class Asset(models.Model):
    """Active Domains for monitoring
    """
    uuid = models.CharField(max_length=36, primary_key=True)

    value = models.CharField(max_length=2048, default='')
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    tag = models.CharField(max_length=500, default='', blank=True)  # comma-separated tags
    related_keyword = models.ForeignKey("keywords.Keyword", on_delete=models.SET_NULL, null=True, blank=True)
    related_project = models.ForeignKey("project.Project", on_delete=models.CASCADE)  # relation to the project
    active = models.BooleanField(null=True)
    description = models.TextField(blank=True, default='', null=True)
    link = models.CharField(max_length=1024, default='', blank=True, null=True)

    type = models.CharField(max_length=100, default='domain')  # can be: domain, ip, url, certificate, starred_domain
    subtype = models.CharField(max_length=100, default='')  # can be: domain, subdomain
    scope = models.CharField(max_length=100, default='external', blank=True, null=True)  # can be: external, internal

    creation_time = models.DateTimeField()  # when was it found to be created
    last_seen_time = models.DateTimeField(blank=True, null=True)  # when was it last seen
    last_scan_time = models.DateTimeField(blank=True, null=True)  # when was it last scanned

    cert_valid = models.BooleanField(default=True)
    cert_wildcard = models.BooleanField(default=False)

    monitor = models.BooleanField(default=False) # monitor this item
    ignore = models.BooleanField(default=False) # ignore these findings in the future (set to invisible and ignore if it shows up again)

    # Redirect field
    redirects_to = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True)

    # IP address fields (populated by get_dns_records)
    ipv4 = models.CharField(max_length=512, blank=True, default='')  # Comma-separated list of IPv4 addresses
    ipv6 = models.CharField(max_length=1024, blank=True, default='')  # Comma-separated list of IPv6 addresses

    # Owner field (comma-separated list of email addresses of responsible people)
    owner = models.TextField(blank=True, default='')

    raw = models.JSONField(null=True, default=None)

    # Registrant/WHOIS info from DomainTools (scan_domaintools)
    registrant_info = models.JSONField(null=True, default=None, blank=True)

    class Meta:
        db_table = 'project_asset'

    def __str__(self):
        return "%s - %s" % (self.value, self.source)
