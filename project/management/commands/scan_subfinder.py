import subprocess
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
import dateparser
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import Asset, Project
from project.scan_utils import resolve_uuids, add_common_scan_arguments
from findings.models import Finding
import tldextract

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

        # Use ThreadPoolExecutor to run scans in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.subfinder_scan_domain, domain.value, project) for domain in domains]
            for future in as_completed(futures):
                future.result()  # This will raise any exceptions caught during the scan

    def subfinder_scan_domain(self, domain, prj):
        self.stdout.write(f'Scanning subdomains for: {domain}')
        try:
            # Create a temporary file to store the Subfinder results
            with tempfile.NamedTemporaryFile(delete=True) as temp_file:
                temp_file_path = temp_file.name
                # print(temp_file_path)
                # Remove the star from the domain if exists
                if domain.startswith("*."):
                    domain = domain[2:]

                # Build the Subfinder command
                command = ['subfinder', '-d', domain, '-oJ', '-o', temp_file_path]

                # print(command)
                # exit(0)

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
                        "type": 'domain',
                        "value": subfinder_domain_name,
                        "source": 'subfinder',
                        "scope": 'external',
                        "link": '',
                        "raw": subfinder_domain,
                        "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                        "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    }
                    # Check if domain or subdomain
                    parsed_obj = tldextract.extract(subfinder_domain_name)
                    if parsed_obj.subdomain:
                        sugg["subtype"] = 'subdomain'
                    else:
                        sugg["subtype"] = 'domain'

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
