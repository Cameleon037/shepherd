from django.db.models import Q
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib import messages
from django.utils.html import escape
from django.utils.timezone import make_aware
from django.http import HttpResponse
from assets.models import Asset, ASSET_FILTER_QUERIES
from project.models import Project
from datetime import datetime
import uuid as imported_uuid
import dateparser
import threading
import csv
import re
from ipaddress import ip_address
from urllib.parse import urlsplit

import tldextract


# Use the bundled public suffix list: asset creation must not need network access.
_extract_domain = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def classify_asset(value, asset_type=None):
    """Return the asset type and domain subtype without changing its value.

    Certificate names can also be valid hostnames, so explicit certificate
    context is preserved. Only domains and wildcard domains have a subtype;
    wildcard labels are excluded when identifying the underlying base domain.
    """
    value = value.strip()
    if asset_type == 'certificate' or value.startswith('-----BEGIN CERTIFICATE-----'):
        return 'certificate', ''

    address = value[1:-1] if value.startswith('[') and value.endswith(']') else value
    try:
        ip_address(address)
        return 'ip', ''
    except ValueError:
        pass

    # Include scheme-relative URLs and host/path values from imports.
    if any(marker in value for marker in ('://', '/', '?', '#')):
        parsed = urlsplit(value if '://' in value or value.startswith('//') else '//' + value)
        if parsed.hostname:
            return 'url', ''

    wildcard = '*' in value
    hostname = '.'.join(label for label in value.split('.') if label != '*')
    domain = _extract_domain(hostname.lower().rstrip('.'))
    subtype = 'subdomain' if domain.subdomain else 'domain'
    return ('starred_domain' if wildcard else 'domain'), subtype


_SERVICE_MAIL_LABEL_RE = re.compile(
    r'^_(dmarc|dmarv|adsp|spf|dkim|domainkeys?|amazonses|submission|smtp'
    r'|autodiscover|imap|imaps)[0-9]*$|^_?mta-sts$|^domainkeys?$'
)
_MAIL_SERVER_LABEL_RE = re.compile(
    r'^(mail|webmail|email|mailjet|acumbamail|smtp|smtpout|pop|imap|imaps|mx'
    r'|relay|autodiscover|send|m[1-9]|em)[0-9]*$'
)
_SERVICE_VALIDATION_LABEL_RE = re.compile(
    r'^_(acme-challenge|pki-validation|dnsauth|esaauth|oktaverification'
    r'|aemverification|github-challenge(-[a-z0-9-]+)?|gitlab-pages-verification-code'
    r'|domainconnect|cpanel-dcv-test-record|cf-custom-hostname|validation-persist)$'
    r'|^asuid$|^_?[0-9a-f]{32,64}$'
)
_SERVICE_DISCOVERY_LABEL_RE = re.compile(
    r'^_(sips?|sipfederationtls|h323cs|h323ls|turns?|stuns?|xmpp-server'
    r'|caldavs?|carddavs?|dep_ws_mutex)$'
)
_WWW_LABEL_RE = re.compile(r'^_?www[0-9]*$')
_NUMERIC_LABEL_RE = re.compile(r'^[0-9]+$')


def classify_category(value, asset_type=None):
    """Return the functional category of a hostname value ('' = uncategorized).

    Categories naming a non-browsable DNS service artifact carry the 'service_'
    prefix so consumers can exclude them with category__startswith='service';
    real hosts (incl. mail servers) keep un-prefixed categories. Structural
    assets (ip/url/certificate) get no category. DNS labels are matched against
    the zone-file evidence in docs/lists/dns_zone_files_11_2026.txt; wildcard
    labels are ignored like in classify_asset().
    """
    if asset_type in ('ip', 'url', 'certificate'):
        return ''
    hostname = '.'.join(l for l in value.strip().lower().rstrip('.').split('.')
                        if l and l != '*')
    if not hostname:
        return ''
    labels = hostname.split('.')
    if any(_SERVICE_VALIDATION_LABEL_RE.match(l) for l in labels):
        return 'service_validation'
    if any(_SERVICE_MAIL_LABEL_RE.match(l) for l in labels):
        return 'service_mail'
    if any(_SERVICE_DISCOVERY_LABEL_RE.match(l) for l in labels):
        return 'service_discovery'
    if any(_MAIL_SERVER_LABEL_RE.match(l) for l in labels):
        return 'mail_server'
    if _WWW_LABEL_RE.match(labels[0]):
        return 'www'
    extracted = _extract_domain(hostname)
    if extracted.subdomain and _NUMERIC_LABEL_RE.match(extracted.subdomain.split('.')[0]):
        return 'numeric_subdomain'
    return ''


def asset_filter_counts(queryset):
    """Counts for the two-level filter bar, keyed by filter-button id.

    The three group ids partition the queryset; the sub ids refine one group.
    Cheap enough to render server-side (14 indexed COUNTs) instead of a
    JSON counts endpoint.
    """
    return {key: queryset.filter(value).count() for key, value in ASSET_FILTER_QUERIES.items()}


def export_assets_csv(project_id, monitored_only=False, scope='external'):
    """
    Export assets to CSV format.
    
    Args:
        project_id: Project ID to filter assets
        monitored_only: If True, only export monitored assets. If False, export all assets.
        scope: Scope filter (default: 'external')
    
    Returns:
        HttpResponse: CSV file response
    """
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return HttpResponse("Project not found", status=404)
    
    # Build queryset
    queryset = Asset.objects.filter(related_project=project, scope=scope)
    
    # Filter by monitor status if specified
    if monitored_only:
        queryset = queryset.filter(monitor=True, ignore=False)
    else:
        queryset = queryset.filter(ignore=False)
    
    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    filename = "monitored_assets.csv" if monitored_only else "suggestions.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    writer = csv.writer(response)
    # Write header
    writer.writerow([
        'UUID', 'Value', 'Related Project', 'Related Keyword', 'Type', 'Subtype', 'Category',
        'Source', 'Description', 'Link', 'Creation Time', 'Active', 'Ignore', 'Monitor', 'Redirects To', 'Scope',
        'IPv4', 'IPv6', 'Owner'
    ])
    # Write data rows
    for asset in queryset:
        writer.writerow([
            asset.uuid,
            asset.value,
            asset.related_project.projectname if asset.related_project else '',
            asset.related_keyword.keyword if asset.related_keyword else '',
            asset.type,
            asset.subtype,
            asset.category,
            asset.source,
            asset.description,
            asset.link,
            asset.creation_time,
            asset.active,
            asset.ignore,
            asset.monitor,
            asset.redirects_to.value if asset.redirects_to else '',
            asset.scope,
            asset.ipv4,
            asset.ipv6,
            asset.owner,
        ])
    return response


def auto_monitor_trusted_assets(project_id, source_list=None):
    """
    Automatically monitor assets that:
    1) Are of type "domain" or "ip"
    2) Are not ignored (ignore=False)
    3) Are active (active=True)
    4) Are not monitored (monitor=False)
    5) Come from a source in source_list (default: subfinder, domaintools)

    Returns:
        tuple: (count_updated, list_of_updated_assets)
    """
    if source_list is None:
        source_list = ['subfinder', 'domaintools']
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return 0, []

    # Build Q objects for source filtering (check if source contains any trusted source)
    source_filters = Q()
    for source in source_list:
        source_filters |= Q(source__icontains=source)
    
    # Base queryset filters (only domain and ip assets)
    queryset = Asset.objects.filter(
        related_project=project,
        type__in=['domain', 'ip'],
        ignore=False,      # Not ignored
        active=True,       # Active
        monitor=False,     # Not monitored
    ).filter(source_filters)  # From trusted sources
    
    # Get assets to update
    assets_to_update = list(queryset)
    
    # Update monitor flag for all matching assets
    count = queryset.update(monitor=True)
    
    return count, assets_to_update


def upload_domains_from_file(request, prj_obj, redirect_url_name, monitor_new=False):
    """
    Shared upload processing for both asset inventory and suggestions.

    Handles file validation, custom source/tags parsing, domain processing
    in a background thread, and source cleanup for custom sources.

    Args:
        request: Django HTTP request with POST data and FILES
        prj_obj: Project object to associate assets with
        redirect_url_name: URL name for redirect (e.g. 'findings:assets')
        monitor_new: If True, set monitor=True for new assets (asset inventory behavior).
                     If False, leave monitor at model default (suggestions behavior).

    Returns:
        HttpResponseRedirect
    """
    redirect_url = reverse(redirect_url_name)

    if not (request.method == "POST" and request.FILES.get("domain_file")):
        messages.error(request, "No file provided or invalid request method.")
        return redirect(redirect_url)

    domain_file = request.FILES["domain_file"]
    custom_source = request.POST.get("custom_source", "").strip()
    tags_input = request.POST.get("tags", "").strip()

    # Validate custom source: only alphanumeric characters and underscores allowed
    if custom_source:
        if not re.match(r'^[a-zA-Z0-9_]+$', custom_source):
            messages.error(request, "Custom source can only contain alphanumeric characters and underscores.")
            return redirect(redirect_url)

    # Validate and parse tags
    tags_list = []
    if tags_input:
        tag_strings = [tag.strip() for tag in tags_input.split(',') if tag.strip()]
        for tag in tag_strings:
            if not re.match(r'^[a-zA-Z0-9_]+$', tag):
                messages.error(request, f"Tag '{tag}' can only contain alphanumeric characters and underscores.")
                return redirect(redirect_url)
            tags_list.append(tag)
        # Remove duplicates while preserving order
        tags_list = list(dict.fromkeys(tags_list))

    # Use custom source if provided, otherwise default to "file_upload"
    upload_source = custom_source if custom_source else "file_upload"

    # Read all lines into memory (always lowercase for consistent matching)
    lines = [escape(line.decode("utf-8").strip().strip('.').lower()) for line in domain_file]

    def process_domains(lines, prj_obj, user, source, tags):
        created_cnt = 0
        updated_cnt = 0
        uploaded_domains = set()  # Track domains in upload file

        for domain in lines:
            if domain:
                uploaded_domains.add(domain.lower())
                defaults = {
                    "related_project": prj_obj,
                    "value": domain,
                    "source": source,
                    "scope": "external",
                    "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                }

                if monitor_new:
                    defaults["monitor"] = not domain.startswith("*")

                item_uuid = imported_uuid.uuid5(imported_uuid.NAMESPACE_DNS, f"{domain}:{prj_obj.id}")
                sobj, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=defaults)

                if created:
                    # Add tags to newly created asset
                    if tags:
                        sobj.tag = ', '.join(tags)
                        sobj.save()
                    created_cnt += 1
                else:
                    # Add source if not already present
                    needs_save = False
                    if source not in sobj.source:
                        sobj.source = sobj.source + ", " + source if sobj.source else source
                        needs_save = True
                    # Add tags if provided
                    if tags:
                        existing_tags = [t.strip() for t in sobj.tag.split(',') if t.strip()] if sobj.tag else []
                        new_tags = [t for t in tags if t not in existing_tags]
                        if new_tags:
                            sobj.tag = ', '.join(existing_tags + new_tags)
                            needs_save = True
                    # For assets (monitor_new=True), ensure existing assets are monitored
                    if monitor_new and not sobj.monitor and not domain.startswith("*"):
                        sobj.monitor = True
                        needs_save = True
                    if needs_save:
                        sobj.save()
                    updated_cnt += 1

        # If custom source was used, remove custom source from assets not in upload
        if source != "file_upload":
            deleted_cnt = 0
            updated_source_cnt = 0
            # Get all assets for this project that contain the custom source
            assets_to_check = Asset.objects.filter(
                related_project=prj_obj,
                source__contains=source
            )

            for asset in assets_to_check:
                # Skip if domain was in the upload file (we just added/updated it)
                if asset.value.lower() in uploaded_domains:
                    continue

                # Remove the custom source from the source field
                source_parts = [s.strip() for s in asset.source.split(',')]
                if source in source_parts:
                    source_parts.remove(source)
                    new_source = ', '.join(source_parts).strip()

                    if not new_source:
                        # Source is empty, delete the asset
                        asset.delete()
                        deleted_cnt += 1
                    else:
                        # Update the source field
                        asset.source = new_source
                        asset.save()
                        updated_source_cnt += 1

            return created_cnt, updated_cnt, deleted_cnt

        return created_cnt, updated_cnt, 0

    # Start processing in a background thread
    thread = threading.Thread(target=process_domains, args=(lines, prj_obj, request.user, upload_source, tags_list))
    thread.start()
    tag_info = f", tags: {', '.join(tags_list)}" if tags_list else ""
    messages.success(request, f"Domains are being uploaded in the background (source: {upload_source}{tag_info}). Please refresh the page after a while to see the results.")
    return redirect(redirect_url)


def ignore_asset(uuid, prj):
    """move asset to ignore list
    """
    a_obj = Asset.objects.get(uuid=uuid, related_project=prj)
    a_obj.monitor = False
    a_obj.ignore = True
    a_obj.save()

    return


def auto_unmonitor_assets(project_id):
    """
    Automatically unmonitor assets that:
    1) Are currently monitored (monitor=True)
    2) Are inactive (active=False)
    
    Args:
        project_id: Project ID. Only processes assets for this project.
    
    Returns:
        tuple: (count_updated, list_of_updated_assets)
    """
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return 0, []
    
    # Find monitored assets that are inactive
    queryset = Asset.objects.filter(
        related_project=project,
        monitor=True,      # Currently monitored
        active=False,      # Inactive
    )
    
    # Get assets to update
    assets_to_update = list(queryset)
    
    # Update monitor flag to False for all matching assets
    count = queryset.update(monitor=False)
    
    return count, assets_to_update
