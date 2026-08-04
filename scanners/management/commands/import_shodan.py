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

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings
from django.utils.timezone import make_aware


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def handle(self, *args, **options):
        total_suggestion_count = 0
        api_url = "https://api.shodan.io/shodan/host/search"
        api_key = settings.SHODAN_API_KEY

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(prj.projectname)
            for kw in prj.keyword_set.all():
                if not kw.enabled:
                    continue
                if kw.ktype != "shodan_keyword":
                    continue
                keyword = html.unescape(kw.keyword)
                self.stdout.write(f"[+] Shodan search for keyword: {keyword}")
                params = {
                    "key": api_key,
                    "query": keyword
                }
                suggestion_count = self.shodan_suggestion_population(api_url, params, kw, prj)
                self.stdout.write(f"[+] suggestions populated: {suggestion_count}")
                total_suggestion_count += suggestion_count

        self.stdout.write(f"[+] total shodan suggestions populated or updated: {total_suggestion_count}")

    def shodan_suggestion_population(self, api_url, params, kw, prj):
        suggestion_count = 0
        page = 1
        total = None
        page_size = 100
        while True:
            try:
                paged_params = params.copy()
                paged_params['page'] = page
                rsp = requests.get(api_url, params=paged_params)
                result = rsp.json()
            except Exception as e:
                self.stdout.write(f"[-] Shodan request failed: {e}")
                break

            if total is None:
                total = result.get('total', 0)
            items = result.get('matches', [])
            if not items:
                break
            for item in items:
                hostnames = item.get('hostnames', [])

                # print(f"page {page} !!!")
                # print(hostnames)
                # continue

                if not hostnames:
                    continue
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

                    if not created:
                        if 'shodan' not in sobj.source:
                            sobj.source = sobj.source + ", shodan"
                        sobj.raw = item
                        sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    sobj.save()
                    suggestion_count += 1

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

            # Shodan returns up to 100 results per page
            if len(items) < page_size:
                break
            page += 1
            time.sleep(1)  # Be polite to the API
        return suggestion_count
