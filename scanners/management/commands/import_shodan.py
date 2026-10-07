import html
import time
import requests
import json
import dateparser
from datetime import datetime, timezone
import uuid
import tldextract

from project.models import Project
from keywords.models import Keyword
from assets.models import Asset
from scanners.scan_utils import add_keyword_id_arguments, filter_keywords

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.timezone import make_aware

# Transient Shodan/CDN failures are retried: connection problems, HTML error
# pages, rate limits and 5xx. Semantic API errors (bad key, no credits, bad
# query) are permanent, so they stop the query immediately.
MAX_ATTEMPTS = 3
MAX_EMPTY_PAGE_RETRIES = 2
RETRY_BACKOFF = 5  # seconds, doubled per attempt
RETRY_STATUS = {408, 429, 500, 502, 503, 504}


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

        add_keyword_id_arguments(parser)

    def handle(self, *args, **options):
        self.verbosity = options['verbosity']
        total_suggestion_count = 0
        api_url = "https://api.shodan.io/shodan/host/search"
        api_key = settings.SHODAN_API_KEY

        self.shodan_api_info(api_key)

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(prj.projectname)
            for kw in filter_keywords(prj.keyword_set.all(), options):
                if not kw.enabled:
                    continue
                if kw.ktype != "shodan_keyword":
                    continue
                keyword = html.unescape(kw.keyword)
                self.stdout.write(f"[+] keyword: {keyword} (id {kw.id})")
                for query in (keyword, f"ssl:{keyword}"):
                    self.stdout.write(f"[+] Shodan search for query: {query}")
                    params = {
                        "key": api_key,
                        "query": query,
                    }
                    suggestion_count = self.shodan_suggestion_population(api_url, params, kw, prj)
                    self.stdout.write(f"[+] suggestions populated: {suggestion_count}")
                    total_suggestion_count += suggestion_count

        self.stdout.write(f"[+] total shodan suggestions populated or updated: {total_suggestion_count}")

    def shodan_get(self, url, params, label):
        """GET a Shodan JSON endpoint, retrying transient failures.

        Returns the parsed response, or None when every attempt failed; the
        reason is written to stdout so a zero-result run is never ambiguous.
        """
        delay = RETRY_BACKOFF
        for attempt in range(1, MAX_ATTEMPTS + 1):
            retryable = False
            try:
                rsp = requests.get(url, params=params, timeout=30)
            except requests.exceptions.RequestException as e:
                reason, retryable = f"request failed: {e}", True
            else:
                try:
                    result = rsp.json()
                except ValueError:
                    reason, retryable = f"non-JSON response (HTTP {rsp.status_code}): {rsp.text[:200]}", True
                else:
                    body = rsp.text[:200]
                    detail = (result.get('error') or body) if isinstance(result, dict) else body
                    if rsp.status_code != 200:
                        reason = f"HTTP {rsp.status_code}: {detail}"
                        retryable = rsp.status_code in RETRY_STATUS
                    elif isinstance(result, dict) and result.get('error'):
                        reason = f"API error: {result['error']}"
                    else:
                        return result
            if retryable and attempt < MAX_ATTEMPTS:
                self.stdout.write(f"[!] shodan {label}: {reason}; retrying in {delay}s (attempt {attempt}/{MAX_ATTEMPTS})")
                time.sleep(delay)
                delay *= 2
            else:
                self.stdout.write(f"[-] shodan {label}: {reason}")
                return None

    def shodan_api_info(self, api_key):
        """Report plan and remaining credits so an empty result set can be explained."""
        if not api_key:
            self.stdout.write("[-] SHODAN_API_KEY is not configured.")
            return
        result = self.shodan_get("https://api.shodan.io/api-info", {"key": api_key}, "api-info")
        if not isinstance(result, dict):
            return
        self.stdout.write(
            f"[+] shodan plan={result.get('plan')} query_credits={result.get('query_credits')} "
            f"scan_credits={result.get('scan_credits')} unlocked={result.get('unlocked')}"
        )
        if not result.get('query_credits'):
            self.stdout.write("[-] no Shodan query credits left; searches return no results.")

    def shodan_suggestion_population(self, api_url, params, kw, prj):
        suggestion_count = 0
        created_count = 0
        updated_count = 0
        pages_fetched = 0
        scanned_matches = 0
        filtered_matches = 0
        matched_hostnames = 0
        page = 1
        total = None
        page_size = 100
        api_error = False
        empty_page_retries = 0

        keyword = html.unescape(kw.keyword).lower()
        while True:
            paged_params = params.copy()
            paged_params['page'] = page
            result = self.shodan_get(api_url, paged_params, f"search '{params['query']}' page {page}")
            if result is None:
                api_error = True
                break

            if total is None:
                total = result.get('total', 0)
                self.stdout.write(f"[+] shodan reports {total} total match(es) for this query")
                if not total:
                    break

            items = result.get('matches', [])
            if not items:
                # Shodan claims results but served an empty page: transient, worth a retry.
                if scanned_matches < total and empty_page_retries < MAX_EMPTY_PAGE_RETRIES:
                    empty_page_retries += 1
                    delay = RETRY_BACKOFF * empty_page_retries
                    self.stdout.write(
                        f"[!] page {page}: shodan reported {total} match(es) but served none; "
                        f"retrying in {delay}s (retry {empty_page_retries}/{MAX_EMPTY_PAGE_RETRIES})"
                    )
                    time.sleep(delay)
                    continue
                self.stdout.write(f"[-] page {page}: shodan reported {total} match(es) but served none")
                break

            pages_fetched += 1
            scanned_matches += len(items)
            page_hostnames = 0
            for item in items:
                hostnames = [h for h in item.get('hostnames', []) if keyword in h.lower()]
                if not hostnames:
                    filtered_matches += 1
                    if self.verbosity >= 2:
                        shown = item.get('hostnames') or [item.get('ip_str')]
                        self.stdout.write(f"    [-] no hostname contains '{keyword}': {', '.join(str(h) for h in shown)}")
                    continue
                page_hostnames += len(hostnames)
                for hostname in hostnames:
                    sugg = {
                        "related_keyword": kw,
                        "related_project": prj,
                        "type": 'domain',
                        "value": hostname,
                        "source": 'shodan',
                        "scope": 'external',
                        "link": f"https://www.shodan.io/host/{hostname}",
                        "raw": item,
                        "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                        "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    }
                    # Check if domain or subdomain
                    parsed_obj = tldextract.extract(hostname)
                    if parsed_obj.subdomain:
                        sugg["subtype"] = 'subdomain'
                    else:
                        sugg["subtype"] = 'domain'

                    item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{hostname}:{prj.id}")
                    sobj, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=sugg)

                    if created:
                        created_count += 1
                    else:
                        updated_count += 1
                        if 'shodan' not in sobj.source:
                            sobj.source = sobj.source + ", shodan"
                        sobj.raw = item
                        sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    sobj.save()
                    suggestion_count += 1
                    matched_hostnames += 1
                    if self.verbosity >= 2:
                        self.stdout.write(f"    [{'new' if created else 'seen'}] {hostname} -> {item.get('ip_str')}:{item.get('port')}")

                    # Add 2nd level domain if hostname is a subdomain
                    # if parsed_obj.subdomain:
                    #     domain = ".".join([parsed_obj.domain, parsed_obj.suffix])
                    #     sugg["finding_subtype"] = 'domain'
                    #     sugg["value"] = domain
                    #     domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{domain}:{prj.id}")
                    #     sobj, created = Asset.objects.get_or_create(uuid=domain_uuid, defaults=sugg)
                    #     if not created:
                    #         if 'shodan' not in sobj.source:
                    #             sobj.source = sobj.source + ", shodan"
                    #         sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    #         sobj.save()
                    #     suggestion_count += 1

            self.stdout.write(f"[+] page {page}: {len(items)} match(es), {page_hostnames} hostname(s) matched '{keyword}'")

            # Shodan returns up to 100 results per page
            if len(items) < page_size:
                break
            page += 1
            empty_page_retries = 0
            time.sleep(1)  # Be polite to the API

        if total and scanned_matches < total:
            self.stdout.write(f"[+] stopped after {pages_fetched} page(s): {scanned_matches} of {total} match(es) retrieved")
        self.stdout.write(
            f"[+] shodan summary: total={total} scanned={scanned_matches} "
            f"dropped_no_keyword_hostname={filtered_matches} "
            f"keyword_hostnames={matched_hostnames} new={created_count} updated={updated_count} "
            f"api_error={api_error}"
        )
        return suggestion_count
