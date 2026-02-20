import subprocess
import json
import tempfile
import os
import time
from collections import deque
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import Asset, Project
from project.scan_utils import resolve_uuids, add_common_scan_arguments
from findings.models import Finding


class Command(BaseCommand):
    help = 'Optimized Nuclei scanner for 8 CPUs / 32GB RAM machines (~30k assets)'

    # Larger chunks = fewer nuclei process starts, better internal scheduling
    CHUNK_SIZE = 500

    # Nuclei tuning: 8x Intel Xeon Platinum 8370C @ 2.80GHz, 32GB RAM
    NUCLEI_CONCURRENCY = 150     # -c   parallel template executions
    NUCLEI_BULK_SIZE = 150       # -bs  hosts in parallel per template
    NUCLEI_RATE_LIMIT = 1500     # -rl  max requests/second
    NUCLEI_TIMEOUT = 7           # -timeout  per-request timeout (s)
    NUCLEI_RETRIES = 1           # -retries
    NUCLEI_MAX_HOST_ERR = 15     # -mhe skip host after N consecutive errors
    NUCLEI_STATS_INTERVAL = 15   # -si  heartbeat interval (s)
    DB_BATCH_SIZE = 500          # bulk_create batch size

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='ID of the project to scan')
        parser.add_argument('--update', action='store_true', help='Update Nuclei engine and templates')
        parser.add_argument('--nt', action='store_true', help='Scan new templates only (--nt)')
        add_common_scan_arguments(parser)
        parser.add_argument('--scope', type=str, help='Filter by scope (external, internal)', required=False)
        parser.add_argument('--new-assets', action='store_true', help='Only scan assets with empty last_scan_time')

    # -------------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------------

    def handle(self, *args, **kwargs):
        if kwargs.get('update'):
            self.update_nuclei()
            return

        domains = self._get_domains_to_scan(**kwargs)
        if not domains.exists():
            self.stdout.write("No active domains found.")
            return

        domain_list = list(domains.iterator(chunk_size=2000))
        total = len(domain_list)
        num_chunks = (total + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        nt_option = kwargs.get('nt')

        self._log_banner(total, num_chunks)
        scan_start = time.time()
        total_findings = 0

        for i in range(0, total, self.CHUNK_SIZE):
            chunk = domain_list[i:i + self.CHUNK_SIZE]
            chunk_idx = (i // self.CHUNK_SIZE) + 1

            self.stdout.write(f'\n--- Chunk {chunk_idx}/{num_chunks} ({len(chunk):,} assets) ---')
            chunk_start = time.time()

            n_findings = self._scan_chunk(chunk, nt_option)
            total_findings += n_findings

            # Per-chunk metrics
            chunk_secs = time.time() - chunk_start
            self.stdout.write(
                f'  Chunk done: {n_findings} findings in {chunk_secs:.0f}s '
                f'({chunk_secs / len(chunk):.2f}s/asset)'
            )

            # Overall progress + ETA
            scanned = min(i + self.CHUNK_SIZE, total)
            elapsed = time.time() - scan_start
            avg = elapsed / scanned
            eta = (total - scanned) * avg
            self.stdout.write(
                f'  Progress: {scanned:,}/{total:,} | '
                f'{total_findings:,} findings | '
                f'{avg:.2f}s/asset | '
                f'ETA {eta / 60:.1f}min'
            )

        self._log_summary(total, total_findings, time.time() - scan_start)

    # -------------------------------------------------------------------------
    # Domain selection (same filters as scan_nuclei.py)
    # -------------------------------------------------------------------------

    def _get_domains_to_scan(self, **kwargs):
        projectid = kwargs.get('projectid')
        scope_filter = kwargs.get('scope')
        new_assets_only = kwargs.get('new_assets')

        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                domains = Asset.objects.filter(monitor=True, ignore=False, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            domains = Asset.objects.filter(monitor=True, ignore=False)

        uuid_list = resolve_uuids(kwargs)
        if uuid_list:
            domains = domains.filter(uuid__in=uuid_list)
        if scope_filter:
            domains = domains.filter(scope=scope_filter)
        if new_assets_only:
            domains = domains.filter(last_scan_time__isnull=True)

        return domains

    # -------------------------------------------------------------------------
    # Scan a chunk of domains
    # -------------------------------------------------------------------------

    def _scan_chunk(self, chunk, nt_option):
        """Scan a chunk of domains. Returns the number of findings."""
        targets_path = results_path = None
        try:
            # Write targets file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                targets_path = f.name
                for asset in chunk:
                    f.write(f'{asset.value}\n')

            # Results file (nuclei -je writes a JSON array here)
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as f:
                results_path = f.name

            # Run nuclei with live output
            findings = self._run_nuclei(targets_path, results_path, nt_option)

            # Persist findings
            scan_time = make_aware(datetime.now())
            self._save_findings(findings, chunk, scan_time, nt_option)

            # Mark assets as scanned (full scans only)
            if not nt_option:
                uuids = [a.uuid for a in chunk]
                Asset.objects.filter(uuid__in=uuids).update(last_scan_time=scan_time)

            return len(findings)

        except Exception as e:
            self.stderr.write(f'  ERROR scanning chunk: {e}')
            return 0

        finally:
            for p in (targets_path, results_path):
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass

    # -------------------------------------------------------------------------
    # Run nuclei subprocess with streamed heartbeat
    # -------------------------------------------------------------------------

    def _run_nuclei(self, targets_path, results_path, nt_option):
        """Run nuclei with optimized flags and stream its output as heartbeat."""
        cmd = [
            'nuclei',
            '-l', targets_path,
            '-je', results_path,
            '-ss', 'host-spray',                        # spray all hosts per template — best for large scopes
            '-c', str(self.NUCLEI_CONCURRENCY),
            '-bs', str(self.NUCLEI_BULK_SIZE),
            '-rl', str(self.NUCLEI_RATE_LIMIT),
            '-timeout', str(self.NUCLEI_TIMEOUT),
            '-retries', str(self.NUCLEI_RETRIES),
            '-mhe', str(self.NUCLEI_MAX_HOST_ERR),
            '-stats',                                    # periodic progress stats
            '-si', str(self.NUCLEI_STATS_INTERVAL),
            '-duc',                                      # skip update check at startup
            '-nc',                                       # no ANSI color codes
        ]
        if nt_option:
            cmd.append('-nt')

        self.stdout.write(f'  CMD: {" ".join(cmd)}')

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr → stdout for a single stream
            text=True,
            bufsize=1,                  # line-buffered
        )

        # Stream output as heartbeat — always print stats/errors, throttle the rest.
        # Keep a tail buffer so we can dump the last lines on failure.
        tail = deque(maxlen=30)
        last_log = time.time()
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            tail.append(line)
            now = time.time()
            is_important = any(kw in line for kw in (
                'Stats', 'templates loaded', 'ERR', 'WRN', 'FTL',
                'error', 'panic', 'Could not',
            ))
            if is_important or (now - last_log) >= 10:
                self.stdout.write(f'  [nuclei] {line}')
                last_log = now

        proc.wait()

        if proc.returncode != 0:
            self.stderr.write(f'\n  Nuclei exited with code {proc.returncode}. Last {len(tail)} output lines:')
            for t in tail:
                self.stderr.write(f'    | {t}')

        # Parse JSON export file — try even on non-zero exit (nuclei may have partial results)
        findings = []
        if os.path.exists(results_path) and os.path.getsize(results_path) > 0:
            with open(results_path, 'r') as f:
                content = f.read().strip()
                if content:
                    findings = json.loads(content)

        if proc.returncode != 0:
            self.stderr.write(
                f'  Nuclei failed (exit {proc.returncode}) but recovered {len(findings)} findings from partial results.'
            )

        return findings

    # -------------------------------------------------------------------------
    # Save findings to DB
    #   Full scan  → delete old + bulk_create (fast for large result sets)
    #   --nt scan  → get_or_create (preserves existing findings)
    # -------------------------------------------------------------------------

    def _save_findings(self, findings, chunk, scan_time, nt_option):
        if not findings:
            return

        domain_map = {a.value: a for a in chunk}
        grouped = self._group_findings_by_domain(findings, domain_map)

        if not nt_option:
            # Full scan: delete existing nuclei findings, then bulk-insert
            uuids = [a.uuid for a in chunk]
            deleted, _ = Finding.objects.filter(asset__uuid__in=uuids, source='nuclei').delete()
            if deleted:
                self.stdout.write(f'  Deleted {deleted:,} old findings')

            # Deduplicate by lookup key, then bulk create
            seen = set()
            objs = []
            for domain, items in grouped.items():
                for item in items:
                    data = self._build_finding_data(domain, item, scan_time)
                    key = (data['asset_name'], data['source'], data['name'], data['type'], data['url'])
                    if key not in seen:
                        seen.add(key)
                        objs.append(Finding(**data))

            if objs:
                Finding.objects.bulk_create(objs, batch_size=self.DB_BATCH_SIZE)
                self.stdout.write(f'  Saved {len(objs):,} findings (bulk)')
        else:
            # --nt scan: upsert individually to preserve existing findings
            count = 0
            for domain, items in grouped.items():
                for item in items:
                    data = self._build_finding_data(domain, item, scan_time)
                    lookup = {
                        'asset': domain,
                        'asset_name': data['asset_name'],
                        'source': data['source'],
                        'name': data['name'],
                        'type': data['type'],
                        'url': data['url'],
                    }
                    defaults = {k: v for k, v in data.items() if k not in lookup}
                    obj, _ = Finding.objects.get_or_create(**lookup, defaults=defaults)
                    obj.scan_date = scan_time
                    obj.last_seen = scan_time
                    obj.save()
                    count += 1
            self.stdout.write(f'  Saved {count:,} findings (get_or_create)')

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _group_findings_by_domain(self, findings, domain_map):
        """Group nuclei findings by their matching domain."""
        grouped = {}
        for f in findings:
            host = f.get('host', '')
            if not host:
                continue
            host = host.split(':')[0]   # strip port (e.g. "example.com:443")
            domain = domain_map.get(host)
            if domain:
                grouped.setdefault(domain, []).append(f)
            else:
                self.stdout.write(f'  [-] No match for host: {host}')
        return grouped

    def _build_finding_data(self, domain, finding, scan_time):
        """Build a dict of Finding fields from a nuclei JSON result."""
        info = finding.get('info', {})
        url = finding.get('url', '') or finding.get('matched-at', '')

        reference = info.get('reference', '')
        if isinstance(reference, list):
            reference = ', '.join(reference)

        solution = info.get('solution', '') or info.get('remediation', '')

        cve = info.get('cve-id', '')
        if not cve:
            cve = info.get('classification', {}).get('cve-id', '')

        cvss_metrics = info.get('cvss-metrics', '')
        if not cvss_metrics:
            cvss_metrics = info.get('classification', {}).get('cvss-metrics', '')

        description = info.get('description', '')
        if url:
            description = f'{description}\n\nURL: {url}' if description else f'URL: {url}'

        return {
            'asset': domain,
            'asset_name': domain.value,
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

    def _log_banner(self, total, num_chunks):
        self.stdout.write(
            f'\n{"=" * 60}\n'
            f'  NUCLEI SCAN (Optimized: 8 CPUs / 32GB RAM)\n'
            f'  Assets: {total:,} | Chunks: {num_chunks} x {self.CHUNK_SIZE:,}\n'
            f'  Concurrency: {self.NUCLEI_CONCURRENCY} | '
            f'Rate limit: {self.NUCLEI_RATE_LIMIT} req/s | '
            f'Bulk size: {self.NUCLEI_BULK_SIZE}\n'
            f'  Timeout: {self.NUCLEI_TIMEOUT}s | '
            f'Max host errors: {self.NUCLEI_MAX_HOST_ERR} | '
            f'Strategy: host-spray\n'
            f'{"=" * 60}'
        )

    def _log_summary(self, total, total_findings, total_secs):
        self.stdout.write(
            f'\n{"=" * 60}\n'
            f'  SCAN COMPLETE\n'
            f'  Duration: {total_secs / 60:.1f} min | Assets scanned: {total:,}\n'
            f'  Findings: {total_findings:,} | Avg: {total_secs / total:.2f}s/asset\n'
            f'{"=" * 60}'
        )

    def update_nuclei(self):
        """Update Nuclei engine and templates."""
        for flag, label in [('-up', 'engine'), ('-ut', 'templates')]:
            result = subprocess.run(['nuclei', flag], capture_output=True, text=True)
            if result.returncode != 0:
                self.stderr.write(f'Error updating {label}: {result.stderr}')
                return
        self.stdout.write("Nuclei engine and templates updated.")
