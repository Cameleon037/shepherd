import hmac
import hashlib
import time
import requests
import tldextract
from collections import defaultdict
from datetime import datetime, timezone

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from project.models import Asset, Project
from project.scan_utils import resolve_uuids, add_common_scan_arguments


class Command(BaseCommand):
    help = 'Fetch registrant information from DomainTools Iris Investigate for monitored domain assets and store in Asset.registrant_info'

    # Delay between API calls to avoid rate limiting (seconds)
    RATE_LIMIT_DELAY = 1.0

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='ID of the project to scan')
        add_common_scan_arguments(parser)
        parser.add_argument('--scope', type=str, help='Filter by scope (e.g., external, internal)', required=False)
        parser.add_argument('--new-assets', action='store_true', help='Only scan assets with empty registrant_info')

    def timestamp(self):
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(self, timestamp, uri):
        params = "".join([settings.DOMAINTOOLS_USER, timestamp, uri])
        return hmac.new(
            settings.DOMAINTOOLS_KEY.encode("utf-8"),
            params.encode("utf-8"),
            digestmod=hashlib.sha1,
        ).hexdigest()

    def _iris_lookup(self, domain):
        """Query Iris Investigate for a single domain. Returns the first result item or None."""
        uri = "/v1/iris-investigate/"
        url = f"https://api.domaintools.com{uri}"
        ts = self.timestamp()
        params = {
            "api_username": settings.DOMAINTOOLS_USER,
            "timestamp": ts,
            "signature": self.sign(ts, uri),
            "domain": domain,
        }
        try:
            rsp = requests.get(url, params=params, timeout=30)
            # print(rsp.json())
            rsp.raise_for_status()
            results = rsp.json()["response"]["results"]
            return results[0] if results else None
        except Exception as e:
            self.stderr.write(f"Iris Investigate failed for {domain}: {e}")
            return None

    def _val(self, field):
        """Safely extract 'value' from an Iris Investigate field.

        Fields are usually {value, count} dicts, but can occasionally be a
        plain string or None depending on the domain/TLD.
        """
        if isinstance(field, dict):
            return field.get("value", "") or ""
        if isinstance(field, str):
            return field
        return ""

    def _build_registrant_info(self, item):
        """Build registrant_info dict from an Iris Investigate result item."""
        reg = item.get("registrant_contact") or {}
        emails = [e["value"] for e in (reg.get("email") or []) if isinstance(e, dict) and e.get("value")]
        email = emails[0] if emails else ""
        return {
            "registrant_org":          self._val(item.get("registrant_org")),
            "registrant_name":         self._val(reg.get("name")),
            "registrant_email":        email,
            "registrant_email_domain": email.split("@")[1].lower() if "@" in email else "",
            "registrant_emails":       emails,
            "registrant_phone":        self._val(reg.get("phone")),
            "registrant_fax":          self._val(reg.get("fax")),
            "registrant_city":         self._val(reg.get("city")),
            "registrant_state":        self._val(reg.get("state")),
            "registrant_postal":       self._val(reg.get("postal")),
            "registrant_country":      self._val(reg.get("country")),
            "registrar":               self._val(item.get("registrar")),
            "registration_created":    self._val(item.get("create_date")),
            "registration_expires":    self._val(item.get("expiration_date")),
            "name_servers":            [self._val(ns.get("host")) for ns in (item.get("name_server") or []) if isinstance(ns, dict)],
            "active":                  item.get("active"),
            "_source":                 "iris-investigate",
        }

    def _root_domain(self, asset_value):
        """Return the registered root domain for WHOIS lookup (strips subdomains)."""
        if not asset_value or asset_value.startswith("*."):
            return None
        parsed = tldextract.extract(asset_value)
        if not parsed.domain or not parsed.suffix:
            return None
        return ".".join([parsed.domain, parsed.suffix])

    def handle(self, *args, **options):
        if not getattr(settings, "DOMAINTOOLS_USER", None) or not getattr(settings, "DOMAINTOOLS_KEY", None):
            raise CommandError("DOMAINTOOLS_USER and DOMAINTOOLS_KEY must be set in settings.")

        projectid = options.get("projectid")
        uuid_list = resolve_uuids(options)
        scope_filter = options.get("scope")
        new_assets_only = options.get("new_assets")

        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                assets = Asset.objects.filter(monitor=True, ignore=False, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            assets = Asset.objects.filter(monitor=True, ignore=False)

        # Only domain-type assets
        assets = assets.filter(type="domain")

        if uuid_list:
            assets = assets.filter(uuid__in=uuid_list)
        if scope_filter:
            assets = assets.filter(scope=scope_filter)
        if new_assets_only:
            assets = assets.filter(registrant_info__isnull=True)

        if not assets.exists():
            self.stdout.write("No domain assets found to scan.")
            return

        # Group assets by root domain — WHOIS registrant data exists only at the
        # registered domain level, so all subdomains share the same record.
        domain_to_assets = defaultdict(list)
        for asset in assets:
            root = self._root_domain(asset.value)
            if root:
                domain_to_assets[root].append(asset)
            else:
                self.stdout.write(f"Skipping (invalid domain): {asset.value}")

        count = 0
        for domain, domain_assets in domain_to_assets.items():
            self.stdout.write(f"Fetching Iris Investigate data for: {domain}")
            item = self._iris_lookup(domain)
            if not item:
                time.sleep(self.RATE_LIMIT_DELAY)
                continue

            info = self._build_registrant_info(item)

            for asset in domain_assets:
                asset.registrant_info = info
                asset.save(update_fields=["registrant_info"])
                self.stdout.write(f"  Updated {asset.value}")
                count += 1

            time.sleep(self.RATE_LIMIT_DELAY)

        self.stdout.write(self.style.SUCCESS(f"Updated registrant_info for {count} asset(s)."))
