import requests
import json
import dateparser
from datetime import datetime, timezone
import uuid
import tldextract

from project.models import Project
from keywords.models import Keyword
from assets.models import Asset

from django.core.management.base import BaseCommand
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

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']
        projects = Project.objects.filter(**project_filter)

        for prj in projects:
            self.stdout.write(prj.projectname)
            for kw in prj.keyword_set.all():

                if not kw.enabled:
                    continue

                if kw.ktype == "crtsh_domain":
                    self.stdout.write("[+] crtsh search for: {}".format(kw.keyword))
                    url = 'https://crt.sh/'
                    params_get = {
                        "output" : "json",
                        "q" : kw.keyword,
                    }
                    suggestion_count = self.crtsh_suggestion_population(url, params_get, kw, prj)
                    self.stdout.write("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

        self.stdout.write("[+] total crtsh suggestions populated or updated: {}".format(total_suggestion_count))


    def crtsh_suggestion_population(self, url, params_get, kw, prj):

        # Debug
        proxies = {}
        verify = True
        # if settings.DEBUG:
        #     proxies["https"] = "http://127.0.0.1:8080"
        #     verify = False

        # Suugesstion count
        suggestion_count = 0

        rsp = requests.get(url, params=params_get, proxies=proxies, verify=verify)
        try:
            results = json.loads(rsp.content)
        except Exception as error:
            print(error)
            print(rsp.text)
            return 0

        # Initialize list of domains that will contain results
        for item in results:
            domains = []
            domains.append(item['common_name'].lower())
            domains += [ domain.lower() for domain in item['name_value'].split("\n")]
            domains = list(set(domains))

            for domain in domains:

                if '@' in domain:
                    continue

                # Create the asset details
                sugg = {
                    "related_keyword": kw,
                    "related_project": prj,
                    "type": 'domain',
                    "value": domain,
                    "source": 'crtsh',
                    "scope": 'external',
                    "active": True,
                    "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                }

                # Check if domain or subdomain
                parsed_obj = tldextract.extract(domain)
                if parsed_obj.subdomain:
                    sugg["subtype"] = 'subdomain'
                else:
                    sugg["subtype"] = 'domain'

                # Add starred domains
                if '*' in domain:
                    sugg["type"] = 'starred_domain'
                    sugg["subtype"] = ''

                # Create asset entry
                domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{domain}:{prj.id}")
                sobj, created = Asset.objects.get_or_create(uuid=domain_uuid, defaults=sugg)

                # In case of update
                if not created:
                    # Build source:
                    if not 'crtsh' in sobj.source:
                        sobj.source = sobj.source + ", crtsh"
                    sobj.active = True
                    sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    # Save the object
                    sobj.save()

                suggestion_count += 1

                # If it's a subdomain, add the associated domain if does not exist in the DB
                parsed_obj = tldextract.extract(domain)
                if parsed_obj.subdomain:

                    # Create a new asset
                    domain = ".".join([parsed_obj.domain, parsed_obj.suffix])
                    sugg["subtype"] = 'domain'
                    sugg["value"] = domain

                    # Asset entry creation
                    domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{domain}:{prj.id}")
                    sobj, created = Asset.objects.get_or_create(uuid=domain_uuid, defaults=sugg)

                    # In case of update
                    if not created:
                        # Build source:
                        if not 'crtsh' in sobj.source:
                            sobj.source = sobj.source + ", crtsh"
                        sobj.active = True
                        sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                        # Save the object
                        sobj.save()

                    suggestion_count += 1

        return suggestion_count
