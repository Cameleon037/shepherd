import html
import time
import requests
import json
import dateparser
from datetime import datetime, timezone
import uuid
import tldextract
import base64

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
        api_url = "https://fofa.info/api/v1/search/all"
        email = settings.FOFA_EMAIL
        key = settings.FOFA_KEY

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(prj.projectname)
            for kw in prj.keyword_set.all():
                if not kw.enabled:
                    continue
                if kw.ktype != "fofa_keyword":
                    continue
                keyword = html.unescape(kw.keyword)
                self.stdout.write(f"[+] FOFA search for keyword: {keyword}")
                # FOFA requires the query to be base64 encoded
                b64_query = base64.b64encode(keyword.encode()).decode()
                params = {
                    "email": email,
                    "key": key,
                    "qbase64": b64_query,
                    "size": 100
                }
                suggestion_count = self.fofa_suggestion_population(api_url, params, kw, prj)
                self.stdout.write(f"[+] suggestions populated: {suggestion_count}")
                total_suggestion_count += suggestion_count

        self.stdout.write(f"[+] total fofa suggestions populated or updated: {total_suggestion_count}")

    def fofa_suggestion_population(self, api_url, params, kw, prj):
        suggestion_count = 0
        try:
            rsp = requests.get(api_url, params=params)
            result = rsp.json()
        except Exception as e:
            self.stdout.write(f"[-] FOFA request failed: {e}")
            return suggestion_count

        results = result.get('results', [])
        for item in results:
            # FOFA returns a list of lists, typically [ip, port, domain, ...]
            ip_str = item[0] if len(item) > 0 else None
            domain = item[2] if len(item) > 2 else None
            if not ip_str:
                continue
            sugg = {
                "related_keyword": kw,
                "related_project": prj,
                "type": 'ip',
                "value": ip_str,
                "source": 'fofa',
                "scope": 'external',
                "link": f"https://fofa.info/result?q={params['qbase64']}",
                "raw": item,
                "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
            }
            sugg["subtype"] = 'host'
            item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{ip_str}:{prj.id}")
            sobj, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=sugg)

            # Build description
            description_list = []
            if domain:
                description_list.append(f"Domain: {domain}")
            description = ", ".join(description_list)
            if sobj.description and (description not in sobj.description):
                sobj.description = ", ".join([str(sobj.description), description])
            else:
                sobj.description = description

            # Build source
            if 'fofa' not in sobj.source:
                sobj.source = sobj.source + ", fofa"

            # FOFA doesn't provide active status, default True
            sobj.active = True

            # In case of update
            if not created:
                sobj.raw = item
                sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))

            sobj.save()
            suggestion_count += 1
        return suggestion_count
