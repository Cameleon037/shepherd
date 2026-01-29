import subprocess
import json
import tempfile
import os
import time
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import Asset, Project
from findings.models import Finding


class Command(BaseCommand):
    help = 'Trigger a Nuclei scan against all Assets domains in a specific project and store the results as Findings objects (Optimized version)'

    CHUNK_SIZE = 1000

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='ID of the project to scan',
        )
        parser.add_argument(
            '--update',
            action='store_true',
            help='Update the Nuclei engine and templates',
        )
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
        if kwargs.get('update'):
            self.update_nuclei()
            self.stdout.write("Nuclei engine and templates updated successfully.")
            return

        domains = self._get_domains_to_scan(**kwargs)
        if not domains.exists():
            self.stdout.write("No active domains found to scan.")
            return

        domain_list = list(domains.iterator(chunk_size=self.CHUNK_SIZE))
        total_domains = len(domain_list)
        self.stdout.write(f'Processing {total_domains} domains in chunks of {self.CHUNK_SIZE}')

        # Process domains sequentially in chunks
        for i in range(0, total_domains, self.CHUNK_SIZE):
            chunk = domain_list[i:i + self.CHUNK_SIZE]
            chunk_number = (i // self.CHUNK_SIZE) + 1
            total_chunks = (total_domains + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
            self.stdout.write(f'Processing chunk {chunk_number}/{total_chunks} ({len(chunk)} domains)')
            self._scan_chunk(chunk, kwargs.get('nt'))

    def _get_domains_to_scan(self, **kwargs):
        """Build and return the queryset of domains to scan based on filters."""
        projectid = kwargs.get('projectid')
        uuids_arg = kwargs.get('uuids')
        scope_filter = kwargs.get('scope')
        new_assets_only = kwargs.get('new_assets')

        # Base queryset
        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                domains = Asset.objects.filter(monitor=True, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            domains = Asset.objects.filter(monitor=True)

        # Apply filters
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            domains = domains.filter(uuid__in=uuid_list)

        if scope_filter:
            domains = domains.filter(scope=scope_filter)

        if new_assets_only:
            domains = domains.filter(last_scan_time__isnull=True)

        return domains

    def _scan_chunk(self, domain_chunk, nt_option):
        """Scan a chunk of domains using Nuclei with -l targets.txt and -ss host-spray."""
        start_time = time.time()
        domain_values = [domain.value for domain in domain_chunk]
        targets_file_path = None
        results_file_path = None

        try:
            # Create targets file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as targets_file:
                targets_file_path = targets_file.name
                for domain_value in domain_values:
                    targets_file.write(f'{domain_value}\n')

            # Create results file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as results_file:
                results_file_path = results_file.name

            # Run Nuclei scan
            findings = self._run_nuclei_scan(targets_file_path, results_file_path, nt_option)

            # Process findings and update domains
            scan_time = make_aware(datetime.now())
            self._process_findings(findings, domain_chunk, scan_time)

            # Update domain scan times only for full scans (not new template scans)
            if not nt_option:
                domain_uuids = [domain.uuid for domain in domain_chunk]
                Asset.objects.filter(uuid__in=domain_uuids).update(last_scan_time=scan_time)

            elapsed_time = time.time() - start_time
            self.stdout.write(f'Completed chunk: {len(domain_chunk)} domains, {len(findings)} findings (took {elapsed_time:.2f}s)')

        except Exception as e:
            elapsed_time = time.time() - start_time
            self.stderr.write(f'Error scanning chunk: {str(e)} (took {elapsed_time:.2f}s)')

        finally:
            # Clean up temp files
            if targets_file_path and os.path.exists(targets_file_path):
                try:
                    os.unlink(targets_file_path)
                except Exception:
                    pass
            if results_file_path and os.path.exists(results_file_path):
                try:
                    os.unlink(results_file_path)
                except Exception:
                    pass

    def _run_nuclei_scan(self, targets_file_path, results_file_path, nt_option):
        """Run Nuclei scan and return parsed findings."""
        command = ['nuclei', '-l', targets_file_path, '-ss', 'host-spray', '-t', '/Users/leo/nuclei-templates/dns/caa-fingerprint.yaml', '-je', results_file_path]
        if nt_option:
            command.append('-nt')

        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f'Nuclei scan failed: {result.stderr}')

        # Parse findings from JSON file (Nuclei outputs a JSON array)
        findings = []
        if os.path.exists(results_file_path) and os.path.getsize(results_file_path) > 0:
            with open(results_file_path, 'r') as f:
                content = f.read().strip()
                if content:
                    findings = json.loads(content)

        return findings

    def _process_findings(self, findings, domain_chunk, scan_time):
        """Process findings in bulk, mapping them to the correct domains."""
        if not findings:
            return

        # Create domain mapping for quick lookup
        domain_map = {domain.value: domain for domain in domain_chunk}

        # Group findings by domain
        findings_by_domain = self._group_findings_by_domain(findings, domain_map)

        # Process findings for each domain using bulk operations
        for domain, domain_findings in findings_by_domain.items():
            self._save_findings_bulk(domain, domain_findings, scan_time)

    def _group_findings_by_domain(self, findings, domain_map):
        """Group findings by their matching domain using the 'host' field."""
        findings_by_domain = {}

        for finding in findings:
            # Use the 'host' field directly from Nuclei results
            host = finding.get('host', '')
            if not host:
                continue

            # Remove port if present (e.g., "perdu.com:443" -> "perdu.com")
            host = host.split(':')[0]

            # Find matching domain
            matched_domain = self._find_matching_domain(host, domain_map)
            if matched_domain:
                if matched_domain not in findings_by_domain:
                    findings_by_domain[matched_domain] = []
                findings_by_domain[matched_domain].append(finding)

        return findings_by_domain

    def _find_matching_domain(self, host, domain_map):
        """Find the domain object that matches the host."""
        # Try exact match first
        if host in domain_map:
            return domain_map[host]

        # # Try subdomain match (host ends with .domain)
        # for domain_value, domain_obj in domain_map.items():
        #     if host.endswith('.' + domain_value):
        #         return domain_obj

        else:
            self.stdout.write(f"[-] No matching domain found for host: {host}")

        return None

    def _save_findings_bulk(self, domain, findings, scan_time):
        """Save findings to database using get_or_create."""
        for finding in findings:
            finding_data = self._build_finding_data(domain, finding, scan_time)
            
            # Separate lookup fields from other fields
            lookup_fields = {
                'domain': domain,
                'domain_name': finding_data['domain_name'],
                'source': finding_data['source'],
                'name': finding_data['name'],
                'type': finding_data['type'],
                'url': finding_data['url'],
            }
            
            # All other fields go in defaults
            defaults = {k: v for k, v in finding_data.items() if k not in lookup_fields}
            
            finding_obj, _ = Finding.objects.get_or_create(**lookup_fields, defaults=defaults)
            
            # Update scan_date and last_seen for both new and existing findings
            finding_obj.scan_date = scan_time
            finding_obj.last_seen = scan_time
            finding_obj.save()

    def _build_finding_data(self, domain, finding, scan_time):
        """Build finding data dictionary from Nuclei finding JSON."""
        info = finding.get('info', {})
        
        # URL: use 'url' if present, otherwise fallback to 'matched-at'
        url = finding.get('url', '') or finding.get('matched-at', '')
        
        # Reference: can be a list or string
        reference = info.get('reference', '')
        if isinstance(reference, list):
            reference = ', '.join(reference)
        
        # Solution: check both 'solution' and 'remediation' fields
        solution = info.get('solution', '') or info.get('remediation', '')
        
        # CVE: check both 'cve-id' and classification
        cve = info.get('cve-id', '')
        if not cve:
            classification = info.get('classification', {})
            cve = classification.get('cve-id', '')
        
        # CVSS metrics: check classification
        cvss_metrics = info.get('cvss-metrics', '')
        if not cvss_metrics:
            classification = info.get('classification', {})
            cvss_metrics = classification.get('cvss-metrics', '')
        
        # Build description with URL info
        description = info.get('description', '')
        if url:
            if description:
                description = f"{description}\n\nURL: {url}"
            else:
                description = f"URL: {url}"
        
        return {
            'domain': domain,
            'domain_name': domain.value,
            'source': 'nuclei',
            'name': info.get('name', 'Unknown'),
            'type': finding.get('type', ''),
            'url': url,
            'description': description,
            'solution': solution,
            'reference': reference,
            'severity': info.get('severity', ''),
            'cve': cve,
            'cvssscore': info.get('cvss-score', ''),
            'cvssmetrics': cvss_metrics,
            'vulnerableAt': info.get('vulnerable_at', ''),
            'vulnerabilityDetails': info.get('details', ''),
            'scan_date': scan_time,
            'last_seen': scan_time,
        }

    def update_nuclei(self):
        """Update Nuclei engine and templates."""
        # Update engine
        command = ['nuclei', '-up']
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            self.stderr.write(f'Error updating nuclei engine: {result.stderr}')
            return

        # Update templates
        command = ['nuclei', '-ut']
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            self.stderr.write(f'Error updating nuclei templates: {result.stderr}')
            return
