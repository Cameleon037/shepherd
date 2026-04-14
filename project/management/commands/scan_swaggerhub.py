import html
import tempfile
import requests
from project.models import Project, Keyword, Asset
from findings.models import Finding
import json

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings

from django.utils.timezone import make_aware
from datetime import datetime

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
        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            for kw in prj.keyword_set.all():
                if not kw.enabled:
                    continue
                keyword = html.unescape(kw.keyword)
                if kw.ktype == "swaggerhub_keyword":
                    self.stdout.write(f"[+] SwaggerHub search: {keyword}")
                    self.swaggerhub_scan(kw, prj)

    def swaggerhub_scan(self, kw, prj):
        keyword = html.unescape(kw.keyword)
        base_url = "https://api.swaggerhub.com/apis"
        headers = {
            "Accept": "application/json"
        }
        limit = 25
        page = 0
        all_apis = []
        total_count = None
        try:
            while True:
                params = {
                    "query": keyword,
                    "limit": limit,
                    "page": page
                }
                response = requests.get(base_url, headers=headers, params=params)
                response.raise_for_status()
                result = response.json()
                apis = result.get("apis", [])
                all_apis.extend(apis)
                if total_count is None:
                    total_count = result.get("totalCount", 0)
                page += 1
                if page*limit >= total_count or not apis:
                    break

            # print(len(all_apis))
            # print(all_apis[0])

            if all_apis:
                self.stdout.write(f"[+] APIs found: {len(all_apis)}")
                for api in all_apis:
                    api_name = api.get("name", "")
                    api_description = api.get("description", "")
                    # api_owner = api.get("owner", "")
                    api_url = ""
                    properties = api.get("properties", [])
                    if isinstance(properties, list):
                        for prop in properties:
                            if isinstance(prop, dict) and "url" in prop:
                                api_url = prop["url"]
                                break
                    self.stdout.write(f'    [+] API name: {api_name}')
                    # self.stdout.write(f'    [+] API owner: {api_owner}')
                    self.stdout.write(f'    [+] API URL: {api_url}')
                    Finding.objects.update_or_create(
                        source='swaggerhub',
                        url=api_url,
                        defaults={
                            'keyword': kw,
                            'name': api_name,
                            'type': 'api',
                            'description': api_description,
                            'scan_date': make_aware(datetime.now()),
                            'last_seen': make_aware(datetime.now()),
                        },
                    )
            else:
                self.stdout.write(f"[+] No APIs found for keyword: {keyword}")

        except Exception as error:
            self.stderr.write(f"[+] Error querying SwaggerHub: {error}")

