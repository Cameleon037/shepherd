import os
import subprocess
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
import dateparser
import yaml
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.utils.timezone import make_aware
from datetime import datetime
from assets.models import Asset
from project.models import Project
from scanners.scan_utils import resolve_uuids, add_common_scan_arguments
from findings.models import Finding

class Command(BaseCommand):
    help = 'Trigger a Subfinder scan against all starred domains suggestions in a specific project and stores the new domains as suggestions'

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='ID of the project to scan', required=True)
        add_common_scan_arguments(parser)

    def handle(self, *args, **kwargs):
        projectid = kwargs.get('projectid')
        uuid_list = resolve_uuids(kwargs)

        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                domains = Asset.objects.filter(scope='external', ignore=False, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            domains = Asset.objects.filter(scope='external', ignore=False)

        if uuid_list:
            domains = domains.filter(uuid__in=uuid_list)
        else:
            domains = domains.filter(type='starred_domain')
            

        if not domains.exists():
            self.stdout.write("No active domains found to scan.")
            return

        provider_config_path = self.build_provider_config()

        # Use ThreadPoolExecutor to run scans in parallel
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.subfinder_scan_domain, domain.value, project, provider_config_path)
                           for domain in domains]
                for future in as_completed(futures):
                    future.result()  # This will raise any exceptions caught during the scan
        finally:
            if provider_config_path:
                os.unlink(provider_config_path)

    def build_provider_config(self):
        """Write a subfinder provider-config.yaml built from Django settings.

        Enables the key-backed passive sources: Shodan and FOFA reuse the keys
        already configured for their discovery imports; Chaos (PDCP),
        VirusTotal, SecurityTrails, Censys and GitHub are opt-in through their
        own settings entries (all free plans suffice). Returns the file path
        (caller deletes it) or None when no key is set, in which case subfinder
        falls back to its keyless sources.
        """
        def setting(name):
            return str(getattr(settings, name, '') or '').strip()

        providers = {}
        if setting('SHODAN_API_KEY'):
            providers['shodan'] = [{'key': setting('SHODAN_API_KEY')}]
        if setting('FOFA_EMAIL') and setting('FOFA_KEY'):
            # subfinder expects fofa keys as "email,key"
            providers['fofa'] = [{'key': f"{setting('FOFA_EMAIL')},{setting('FOFA_KEY')}"}]
        if setting('PDCP_API_KEY'):
            providers['chaos'] = [{'key': setting('PDCP_API_KEY')}]
        if setting('VIRUSTOTAL_API_KEY'):
            providers['virustotal'] = [{'key': setting('VIRUSTOTAL_API_KEY')}]
        if setting('SECURITYTRAILS_API_KEY'):
            providers['securitytrails'] = [{'key': setting('SECURITYTRAILS_API_KEY')}]
        if setting('CENSYS_ID') and setting('CENSYS_SECRET'):
            providers['censys'] = [{'id': setting('CENSYS_ID'), 'secret': setting('CENSYS_SECRET')}]
        github_token = setting('SUBFINDER_GITHUB_TOKEN') or setting('GHLEAKS_TOKEN')
        if github_token:
            providers['github'] = [{'token': [github_token]}]

        if not providers:
            return None

        fd, path = tempfile.mkstemp(prefix='subfinder_providers_', suffix='.yaml')
        os.chmod(path, 0o600)
        with os.fdopen(fd, 'w') as f:
            yaml.safe_dump(providers, f)
        self.stdout.write(f"[+] subfinder provider config enabled: {', '.join(sorted(providers))}")
        return path

    def subfinder_scan_domain(self, domain, prj, provider_config_path=None):
        self.stdout.write(f'Scanning subdomains for: {domain}')
        try:
            # Create a temporary file to store the Subfinder results
            with tempfile.NamedTemporaryFile(delete=True) as temp_file:
                temp_file_path = temp_file.name
                # print(temp_file_path)
                # Remove the star from the domain if exists
                if domain.startswith("*."):
                    domain = domain[2:]

                # Build the Subfinder command: -all enables every source,
                # including the key-backed ones (provider config below) and
                # the slower/recursive providers; -silent keeps stdout to the
                # JSONL results file.
                command = ['subfinder', '-d', domain, '-oJ', '-o', temp_file_path,
                           '-all', '-silent']
                if provider_config_path:
                    command += ['-pc', provider_config_path]

                # Trigger Subfinder scan
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                if result.returncode != 0:
                    self.stderr.write(f'Error scanning domain {domain}: {result.stderr}')
                    return

                # for line in temp_file:
                #     print(line)

                for line in temp_file:
                    subfinder_domain = json.loads(line)
                    subfinder_domain_name = subfinder_domain['host'].lower()

                    # Create the asset details
                    sugg = {
                        "related_project": prj,
                        "value": subfinder_domain_name,
                        "source": 'subfinder',
                        "scope": 'external',
                        "link": '',
                        "raw": subfinder_domain,
                        "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                        "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    }
                    # Create suggestion entry
                    subfinder_domain_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{subfinder_domain_name}:{prj.id}")
                    sobj, created = Asset.objects.get_or_create(uuid=subfinder_domain_uuid, related_project=prj, defaults=sugg)

                    if created:
                        print(f"Add new suggestion: {subfinder_domain_name} to project {prj.projectname}")
                    else:
                        sobj.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                        if not 'subfinder' in sobj.source:
                            sobj.source = sobj.source + ", subfinder"
                        sobj.save()
                        print(f"Update suggestion: {subfinder_domain_name} in project {prj.projectname}")

        except Exception as e:
            self.stderr.write(f'Exception scanning domain {domain}: {str(e)}')
