import hmac
import hashlib
import html
import time
import requests
from urllib.parse import urlencode, quote_plus
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

    def timestamp(self):
        return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def sign(self, timestamp, uri):
        params = "".join([settings.DOMAINTOOLS_USER, timestamp, uri])
        return hmac.new(settings.DOMAINTOOLS_KEY.encode("utf-8"), params.encode("utf-8"), digestmod=hashlib.sha1).hexdigest()

    def handle(self, *args, **options):
        total_suggestion_count = 0
        uri = "/v1/iris-investigate/"
        host = "api.domaintools.com"

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(prj.projectname)
            for kw in prj.keyword_set.all():

                if not kw.enabled:
                    continue

                keyword = html.unescape(kw.keyword)
                if kw.ktype == "domaintools_registrant_org":
                    # Per registrant
                    self.stdout.write("[+] domaintools search per registrant: {}".format(keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "registrant" : keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    self.stdout.write("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                    # Per registrant org
                    self.stdout.write("[+] domaintools search per registrant organization: {}".format(keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "registrant_org" : keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    self.stdout.write("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                if kw.ktype == "domaintools_registrant_email":
                    # Per e-mail
                    self.stdout.write("[+] domaintools search per registrant email: {}".format(keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "email" : keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    self.stdout.write("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                if kw.ktype == "domaintools_registrant_email_domain":
                    # Per e-mail domain
                    self.stdout.write("[+] domaintools search per registrant email domain: {}".format(keyword))
                    params_get = {
                        "api_username" : settings.DOMAINTOOLS_USER,
                        "email_domain" : keyword,
                    }
                    suggestion_count = self.domaintools_suggestion_population(host, uri, params_get, kw, prj)
                    self.stdout.write("[+] suggestions populated: {}".format(suggestion_count))
                    total_suggestion_count += suggestion_count

                else:
                    continue

        self.stdout.write("[+] total domaintools suggestions populated or updated: {}".format(total_suggestion_count))


    def domaintools_suggestion_population(self, host, uri, params_get, kw, prj):

        # API authentication: signature
        url = "https://{0}{1}".format(host, uri)
        ts = self.timestamp()
        signature = self.sign(ts, uri)
        params_get["timestamp"] = ts
        params_get["signature"] = signature

        # Debug
        proxies = {}
        verify = True
        # if settings.DEBUG:
        #     proxies["https"] = "http://127.0.0.1:8080"
        #     verify = False

        # Error count
        err_cnt = 0
        err_limit = 5

        # Suugesstion count
        suggestion_count = 0

        rsp = requests.get(url, params=params_get, proxies=proxies, verify=verify)
        result = json.loads(rsp.content)

        # Initialize list of items that will conatin doaintools results
        items = []
        if result["response"]["limit_exceeded"]:
            self.stdout.write("[-] domaintools results limit exceeded -> refine the query")
            return suggestion_count
        else:
            items += result['response']['results']
            while result['response']['has_more_results']:
                try:
                    params_get["position"] = result["response"]["position"]
                    rsp = requests.get(url, params=params_get, proxies=proxies, verify=verify)
                    result = json.loads(rsp.content)
                    # Add results of the next pages
                    items += result['response']['results']
                    err_cnt = 0
                except:
                    self.stdout.write("[-] request failed: {}, {}. Waiting 1 sec..".format(rsp, rsp.text))
                    time.sleep(0.5)
                    if err_cnt >= err_limit:
                        self.stdout.write("[-] Too many failed requests, skip method")
                        break
                    else:
                        err_cnt += 1
        
        # Process the results and add them to the database        
        for item in items:
            
            if '@' in item['domain']:
                continue

            # Create the asset details
            sugg = {
                "related_keyword": kw,
                "related_project": prj,
                "type": 'domain',
                "value": item['domain'],
                "source": 'domaintools',
                "scope": 'external',
                "link": '',
                "raw": item,
                "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
            }
            # Check if domain or subdomain
            parsed_obj = tldextract.extract(item['domain'])
            if parsed_obj.subdomain:
                sugg["subtype"] = 'subdomain'
            else:
                sugg["subtype"] = 'domain'

            # Create suggestion entry
            item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{item['domain']}:{prj.id}")
            sobj, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=sugg)

            # Build description
            description_list = []
            if item['registrant_org']['value']:
                description_list.append("Registrant Org: {}".format(item['registrant_org']['value']))
            if item['registrant_contact']['email']:
                emails = []
                for email in item['registrant_contact']['email']:
                    emails.append(email['value'])
                description_list.append("Registrant Emails: {}".format(", ".join(emails)))
            description = ", ".join(description_list)
            if sobj.description and (not description in sobj.description):
                sobj.description = ", ".join([str(sobj.description), description])
            else: 
                sobj.description = description

            # Build source:
            if not 'domaintools' in sobj.source:
                sobj.source = sobj.source + ", domaintools"

            # Check if active
            if str(item['active']) == "True":
                sobj.active = True
            elif str(item['active']) == "False":
                sobj.active = False

            # In case of update
            if not created:
                sobj.raw = item
                sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))

            # Save the object
            sobj.save()

            suggestion_count += 1

            # If it's a subdomain, add the associated domain if does not exist in the DB
            parsed_obj = tldextract.extract(item['domain'])
            if parsed_obj.subdomain:

                # Create a new asset
                domain = ".".join([parsed_obj.domain, parsed_obj.suffix])
                sugg["subtype"] = 'domain'
                sugg["value"] = domain
                domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{domain}:{prj.id}")
                sobj, created = Asset.objects.get_or_create(uuid=domain_uuid, defaults=sugg)

                if not created:
                    if str(item['active']) == "True":
                        sobj.active = True
                    elif str(item['active']) == "False":
                        sobj.active = False
                    sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    # Save the object
                    sobj.save()

                suggestion_count += 1

        return suggestion_count
