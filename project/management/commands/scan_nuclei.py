import subprocess
import json
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import Asset, Project
from findings.models import Finding


class Command(BaseCommand):
    help = 'Trigger a Nuclei scan against all Assets domains in a specific project and store the results as Findings objects'

    def add_arguments(self, parser):
        # Add an optional projectid argument
        parser.add_argument(
            '--projectid',
            type=int,
            help='ID of the project to scan',
        )
        # Add an optional argument for updating Nuclei
        parser.add_argument(
            '--update',
            action='store_true',
            help='Update the Nuclei engine and templates',
        )
        # Add an optional argument for triggering the scan with the "-nt" option
        parser.add_argument(
            '--nt',
            action='store_true',
            help='Trigger the Nuclei scan with the "--nt" option',
        )
        parser.add_argument(
            '--uuids',
            type=str,
            help='Comma separated list of Asset UUIDs to process',
            required=False,
        )
        parser.add_argument(
            '--scope',
            type=str,
            help='Filter by scope (e.g., external, internal)',
            required=False,
        )
        parser.add_argument(
            '--new-assets',
            action='store_true',
            help='Only scan assets with empty last_scan_time',
        )

    def handle(self, *args, **kwargs):
        projectid = kwargs.get('projectid')
        update = kwargs.get('update')
        nt_option = kwargs.get('nt')
        uuids_arg = kwargs.get('uuids')
        scope_filter = kwargs.get('scope')
        new_assets_only = kwargs.get('new_assets')

        # Handle the update argument
        if update:
            self.update_nuclei()
            self.stdout.write("Nuclei engine and templates updated successfully.")
            return

        # Fetch active domains based on the project ID
        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                active_domains = Asset.objects.filter(monitor=True, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            active_domains = Asset.objects.filter(monitor=True)

        # Filter by uuids if provided
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            active_domains = active_domains.filter(uuid__in=uuid_list)

        # Filter by scope if provided
        if scope_filter:
            active_domains = active_domains.filter(scope=scope_filter)

        # Filter by new_assets_only if set
        if new_assets_only:
            active_domains = active_domains.filter(last_scan_time__isnull=True)

        if not active_domains.exists():
            self.stdout.write("No active domains found to scan.")
            return

        # Use ThreadPoolExecutor to run scans in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.scan_domain, domain, nt_option) for domain in active_domains]
            for future in as_completed(futures):
                future.result()  # This will raise any exceptions caught during the scan

    def scan_domain(self, domain, nt_option):
        self.stdout.write(f'Scanning domain: {domain.value}')
        try:
            # Create a temporary file to store the Nuclei scan results
            findings = []
            with tempfile.NamedTemporaryFile(delete=True) as temp_file:
                temp_file_path = temp_file.name
                # print(temp_file_path)

                # Build the Nuclei command
                command = ['nuclei', '-u', domain.value, '-je', temp_file_path]
                if nt_option:
                    command.append('-nt')  # Add the "-nt" option if specified

                # Trigger Nuclei scan
                result = subprocess.run(command, capture_output=True, text=True)
                if result.returncode != 0:
                    self.stderr.write(f'Error scanning domain {domain.value}: {result.stderr}')
                    return

                findings = json.load(temp_file)

            for finding in findings:
                # Store the result as a Finding object
                content = {
                    'domain': domain,
                    'domain_name': domain.value,

                    'source': 'nuclei',
                    'name': finding.get('info', {}).get('name', 'Unknown'),
                    'type': finding.get('type', ''),
                    'url': finding.get('url', ''),

                    'description': finding.get('info', {}).get('description', ''),
                    'solution': finding.get('info', {}).get('solution', ''),
                    'reference': finding.get('info', {}).get('reference', ''),

                    'severity': finding.get('info', {}).get('severity', ''),
                    'cve': finding.get('info', {}).get('cve-id', ''),
                    'cvssscore': finding.get('info', {}).get('cvss-score', ''),
                    'cvssmetrics': finding.get('info', {}).get('cvss-metrics', ''),
                    'vulnerableAt': finding.get('info', {}).get('vulnerable_at', ''),
                    'vulnerabilityDetails': finding.get('info', {}).get('details', ''),
                }
                finding_obj, _ = Finding.objects.get_or_create(**content)
                finding_obj.scan_date = make_aware(datetime.now())
                finding_obj.last_seen = finding_obj.scan_date
                finding_obj.save()

            domain.last_scan_time = make_aware(datetime.now())
            domain.save()
            if len(findings):
                self.stdout.write(f'Stored and deduplicated {len(findings)} findings for domain {domain.value}')
            else:
                self.stdout.write(f'No findings for domain {domain.value}')
        except Exception as e:
            self.stderr.write(f'Exception scanning domain {domain.value}: {str(e)}')

    def update_nuclei(self):

        # Nuclei engine update
        command = ['nuclei', '-up']
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            self.stderr.write(f'Error updating nuclei engine: {result.stderr}')
            return
        
        # Nuclei templates update
        command = ['nuclei', '-ut']
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            self.stderr.write(f'Error updating nuclei templates: {result.stderr}')
            return