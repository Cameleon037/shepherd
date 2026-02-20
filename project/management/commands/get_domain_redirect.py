import socket
import uuid
import dateparser
import requests
import tldextract
from urllib.parse import urlparse
from django.core.management.base import BaseCommand
from project.models import Asset
from project.scan_utils import resolve_uuids, add_common_scan_arguments
from datetime import datetime, timezone
from django.utils.timezone import make_aware
from concurrent.futures import ThreadPoolExecutor, as_completed


class Command(BaseCommand):
    help = "Check for domain redirections and update the redirects_to field in Asset objects."

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='Filter by specific project ID')
        add_common_scan_arguments(parser)

    def handle(self, *args, **kwargs):
        # Filter suggestions by project ID if provided
        project_filter = {}
        if kwargs['projectid']:
            project_filter['related_project__id'] = kwargs['projectid']

        uuid_list = resolve_uuids(kwargs)

        assets = Asset.objects.exclude(active=False).filter(**project_filter).filter(scope='external', type='domain')
        if uuid_list:
            assets = assets.filter(uuid__in=uuid_list)

        def process_asset(asset, projectid):
            domain = asset.value
            final_domain = self.check_redirect(domain)

            final_asset = None
            if final_domain and final_domain != domain:

                # Create the asset details for the final domain
                asset_data = {
                    "type": "domain",
                    "scope": "external",
                    "related_project": asset.related_project,
                    "source": "redirect",
                    "description": f"Redirected from {domain}",
                    "active": True,
                    "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                }

                # Check if domain or subdomain
                parsed_obj = tldextract.extract(final_domain)
                if parsed_obj.subdomain:
                    asset_data["subtype"] = 'subdomain'
                else:
                    asset_data["subtype"] = 'domain'

                # Create asset entry
                final_domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{final_domain}:{projectid}")
                final_asset, created = Asset.objects.get_or_create(
                    value = final_domain,
                    uuid = final_domain_uuid,
                    defaults=asset_data,
                )

                if not created:
                    final_asset.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    if not 'redirect' in final_asset.source:
                        final_asset.source = final_asset.source + ", redirect"
                    if not asset_data["description"] in final_asset.description:
                        final_asset.description = "\n".join([final_asset.description, asset_data["description"]])
                    final_asset.save()

                self.stdout.write(f"{domain} redirects to {final_domain}")
                # exit(0)
            else:
                self.stdout.write(f"{domain} does not redirect.")

            # Update the redirects_to field
            asset.redirects_to = final_asset
            asset.save()

        # Parallelize the processing of assets
        projectid = kwargs.get('projectid')
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(process_asset, asset, projectid) for asset in assets]
            for future in as_completed(futures):
                future.result()  # Raise exceptions if any

    def check_redirect(self, domain):
        """
        Check if the domain redirects and return the final domain.
        """
        for scheme, port in [("https", 443), ("http", 80)]:
            url = f"{scheme}://{domain}"
            try:
                # Check if the port is open
                with socket.create_connection((domain, port), timeout=5):
                    # Follow redirections
                    response = requests.get(url, allow_redirects=True, timeout=10)
                    final_url = response.url
                    parsed_url = urlparse(final_url)
                    return parsed_url.hostname  # Return the final domain (without port)
            except (socket.error, requests.RequestException):
                continue  # Try the next scheme/port
            except Exception as e:
                self.stdout.write(f"Error checking url: {url}: {e}")
                continue
        return None