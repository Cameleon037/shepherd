from django.db import models

# Create your models here.

class Project(models.Model):
    """Class describes a project or company that we want to monitor
    """
    projectname = models.CharField(max_length=1024, unique=True)
    description = models.TextField(default='')
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "%s" % (self.projectname)

class Keyword(models.Model):
    """Keyword describing a company (can be the name)
    """
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    keyword = models.CharField(max_length=1024)  # keyword to use as a starting point
    description = models.TextField(default='')
    enabled = models.BooleanField(default=True)  # disable keywords that should not be used
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    ktype = models.CharField(max_length=1024, default='registrant_org')  # what type of keyword, e.g. name, domain, ...

    def __str__(self):
        return "%s" % (self.keyword)

# class Suggestion(models.Model):
#     """Potentially fitting domains for project
#     """
#     related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE, null=True, blank=True)
#     related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
#     finding_type = models.CharField(max_length=100, default='domain')  # can be: domain, ip, url, certificate, starred_domain
#     finding_subtype = models.CharField(max_length=100, default='domain')  # can be: domain, subdomain
#     value = models.CharField(max_length=2048, default='')
#     uuid = models.CharField(max_length=36, primary_key=True)
#     source = models.CharField(max_length=200, default='')  # can be cert.sh for example
#     creation_time = models.DateTimeField()  # when was it found to be created
#     last_seen_time = models.DateTimeField(blank=True, null=True)  # when was it last seen
#     description = models.TextField(default='', blank=True, null=True)
#     active = models.BooleanField(null=True)
#     link = models.CharField(max_length=1024, default='', blank=True, null=True)
#     cert_valid = models.BooleanField(default=True)
#     cert_wildcard = models.BooleanField(default=False)
#     ignore = models.BooleanField(default=False) # ignore these findings in the future (set to invisible and ignore if it shows up again)
#     monitor = models.BooleanField(default=False) # ignore these findings as they are already on the monitoring list

#     # Redirect fields
#     redirect_to = models.ForeignKey("Suggestion", on_delete=models.SET_NULL, null=True, blank=True)

#     raw = models.JSONField(null=True, default=None)
    
#     def __str__(self):
#         return "%s - %s" % (self.finding_type, self.value)

class Asset(models.Model):
    """Active Domains for monitoring
    """
    uuid = models.CharField(max_length=36, primary_key=True)

    value = models.CharField(max_length=2048, default='')
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    tag = models.CharField(max_length=500, default='', blank=True)  # comma-separated tags
    related_keyword = models.ForeignKey("Keyword", on_delete=models.SET_NULL, null=True, blank=True)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
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
    redirects_to = models.ForeignKey("Asset", on_delete=models.SET_NULL, null=True, blank=True)
    
    # IP address fields (populated by get_dns_records)
    ipv4 = models.CharField(max_length=512, blank=True, default='')  # Comma-separated list of IPv4 addresses
    ipv6 = models.CharField(max_length=1024, blank=True, default='')  # Comma-separated list of IPv6 addresses
    
    # Owner field (comma-separated list of email addresses of responsible people)
    owner = models.TextField(blank=True, default='')
    
    raw = models.JSONField(null=True, default=None)
    
    def __str__(self):
        return "%s - %s" % (self.value, self.source)

class DNSRecord(models.Model):
    """DNS records for assets
    """
    related_asset = models.ForeignKey("Asset", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)
    record_type = models.CharField(max_length=10)  # A, AAAA, CNAME, MX, TXT, NS, SOA, PTR
    record_value = models.TextField()  # The actual DNS record value
    ttl = models.IntegerField(null=True, blank=True)  # Time to live
    creation_time = models.DateTimeField(auto_now_add=True)
    last_checked = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['related_asset', 'record_type', 'record_value']
    
    def __str__(self):
        return f"{self.related_asset.value} - {self.record_type}: {self.record_value[:50]}"

class ActiveIP(models.Model):
    """Active IPs for monitoring
    """
    related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    value = models.CharField(max_length=2048, default='')
    uuid = models.CharField(max_length=36, primary_key=True)
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    creation_time = models.DateTimeField()  # when was it found to be created
    last_scan_time = models.DateTimeField(blank=True, null=True)  # when was it last scanned
    description = models.TextField(blank=True, default='', null=True)
    link = models.CharField(max_length=1024)
    monitor = models.BooleanField(default=True) # monitor this item

class ActiveCertificate(models.Model):
    """Active Certificates for monitoring
    """
    related_keyword = models.ForeignKey("Keyword", on_delete=models.CASCADE)
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    value = models.CharField(max_length=2048, default='')
    uuid = models.CharField(max_length=36, primary_key=True)
    source = models.CharField(max_length=200, default='')  # can be cert.sh for example
    creation_time = models.DateTimeField()  # when was it found to be created
    description = models.TextField(default='')
    link = models.CharField(max_length=1024)
    cert_valid = models.BooleanField(default=True)
    cert_wildcard = models.BooleanField(default=False)
    monitor = models.BooleanField(default=True) # monitor this item


class RelatedIP(models.Model):
    related_domains = models.ForeignKey("Asset", on_delete=models.CASCADE)
    ip = models.GenericIPAddressField()


class RelatedDomain(models.Model):
    related_ips = models.ForeignKey("ActiveIP", on_delete=models.CASCADE)
    domain = models.CharField(max_length=2048, default='')

class Job(models.Model):
    COMMAND_CHOICES = [
        ('get_domain_redirect', 'Get Domain Redirect'),
        ('scan_nmap', 'Scan Nmap'),
        # ...add more as needed
    ]
    
    related_project = models.ForeignKey("Project", on_delete=models.CASCADE)  # relation to the project
    command = models.CharField(max_length=100, choices=COMMAND_CHOICES)
    args = models.TextField(blank=True, default='')

    status = models.CharField(max_length=20, default='pending')  # pending, running, finished, failed
    output = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    user = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
