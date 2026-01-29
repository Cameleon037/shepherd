from django.db import models
from project.models import Asset, Keyword

# Create your models here.

class Port(models.Model):
    """class to describe open ports
    """
    domain = models.ForeignKey(Asset, on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=2048, default='')
    scan_date = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=50, default='info')
    port = models.IntegerField()
    banner = models.CharField(max_length=2048, default='')
    status = models.CharField(max_length=50, default='open')
    product = models.CharField(max_length=2048, default='')
    cpe = models.CharField(max_length=2048, default='')
    raw = models.JSONField(null=True)

    def __str__(self):
        return "%i - %s - %s - %s" % (self.id, self.port, self.banner, self.domain.value)

class Finding(models.Model):
    """class to describe a security finding
    """
    domain = models.ForeignKey(Asset, on_delete=models.CASCADE, null=True)
    keyword = models.ForeignKey(Keyword, on_delete=models.CASCADE, null=True)
    domain_name = models.CharField(max_length=2048, default='')

    # Finding details
    source = models.CharField(max_length=200, default='nuclei')
    name = models.CharField(max_length=2048, default='')
    type = models.CharField(max_length=2048, default='')
    url = models.CharField(max_length=2048, default='')
    description = models.TextField(default='')
    solution = models.TextField(default='')
    reference = models.CharField(max_length=2048, default='')
    ignore = models.BooleanField(default=False)
    comment = models.TextField(default='', blank=True, null=True)

    # Severity fields
    severity = models.CharField(max_length=50, default='', null=True)
    cve = models.CharField(max_length=1024, default='', null=True)
    cvssscore = models.CharField(max_length=1024, default='', null=True)
    cvssmetrics = models.CharField(max_length=1024, default='', null=True)
    vulnerableAt = models.CharField(max_length=2048, default='', null=True)
    vulnerabilityDetails = models.CharField(max_length=4096, default='', blank=True, null=True)

    # Time related fields
    scan_date = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    last_reported = models.DateTimeField(blank=True, null=True)

    reported = models.BooleanField(default=False)
    raw = models.JSONField(null=True)

    def __str__(self):
        return "%i - %s - %s - %s" % (self.id, self.name, self.severity, self.domain.value)

class Screenshot(models.Model):
    """
    Model to store screenshots and related metadata for a URL.
    """
    url = models.CharField(max_length=2048, primary_key=True)
    domain = models.ForeignKey(Asset, on_delete=models.CASCADE, null=True, default=None)
    technologies = models.CharField(max_length=2048, blank=True, default='')
    screenshot_base64 = models.TextField(blank=True, default='')  # base64-encoded image
    title = models.CharField(max_length=2048, blank=True, default='')
    webserver = models.CharField(max_length=2048, blank=True, default='')
    host_ip = models.CharField(max_length=256, blank=True, default='')
    status_code = models.CharField(max_length=32, blank=True, default='')
    response_body = models.TextField(blank=True, default='')
    failed = models.BooleanField(default=False)

    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Screenshot for {self.url} at {self.date}"
