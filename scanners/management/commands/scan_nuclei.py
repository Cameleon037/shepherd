import subprocess
import json
import tempfile
import os
import re
import time
from collections import deque
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q
from django.utils.timezone import make_aware
from datetime import datetime, timedelta
from assets.models import Asset
from project.models import Project
from scanners.scan_utils import resolve_uuids, add_common_scan_arguments
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
    NUCLEI_STATS_INTERVAL = 60   # -si  heartbeat interval (s)
    DB_BATCH_SIZE = 500          # bulk_create batch size

    # FP filtering: only high-confidence findings reach the DB.
    # default-login checks are deliberately kept (user decision); dos must never run on prod.
    NUCLEI_SEVERITY = 'medium,high,critical'
    NUCLEI_EXCLUDE_TAGS = 'dos,fuzz,brute-force'
    # Only print nuclei lines whose gologger level tag (line start) is interesting;
    # substring matching leaks INF skip lines whose URL payloads contain "error".
    NUCLEI_LEVEL_TAGS = ('[ERR]', '[WRN]', '[FTL]', '[PAN]')
    NUCLEI_PANIC_PREFIXES = ('panic', 'fatal error:')
    # Stats summary line (no level tag): "[H:MM:SS] | Templates: …"
    NUCLEI_STATS_RE = re.compile(r'^\[\d{1,3}:\d{2}:\d{2}\] \| Templates:')
    # For duplicate collapse: URLs/hosts differ per template, message does not.
    NUCLEI_URL_RE = re.compile(r'https?://\S+')

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='ID of the project to scan')
        parser.add_argument('--update', action='store_true', help='Update Nuclei engine and templates')
        parser.add_argument('--nt', action='store_true', help='Scan new templates only (--nt)')
        add_common_scan_arguments(parser)
        parser.add_argument('--scope', type=str, help='Filter by scope (external, internal)', required=False)
        parser.add_argument('--new-assets', action='store_true', help='Only scan assets with empty last_scan_time')
        parser.add_argument(
            '--stale-days',
            type=int,
            metavar='DAYS',
            help='Only scan assets never scanned or last scanned more than DAYS days ago',
            required=False,
        )
        parser.add_argument(
            '--check',
            action='store_true',
            help='Re-probe open findings with the exact nuclei template that found them; '
                 'mark those that no longer reproduce as fixed',
        )
        parser.add_argument(
            '--check-severity',
            type=str,
            default='high,critical',
            metavar='LIST',
            help='Comma-separated severities of open findings to re-probe (default: high,critical)',
        )

    # -------------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------------

    def handle(self, *args, **kwargs):
        if kwargs.get('update'):
            self.update_nuclei()
            return

        if kwargs.get('check'):
            if kwargs.get('nt'):
                raise CommandError('--check cannot be combined with --nt')
            self._check_findings(**kwargs)
            return

        domains = self._get_domains_to_scan(**kwargs)
        if not domains.exists():
            self.stdout.write("No active domains found.")
            return

        domain_list = list(domains.iterator(chunk_size=2000))
        total = len(domain_list)
        num_chunks = (total + self.CHUNK_SIZE - 1) // self.CHUNK_SIZE
        nt_option = kwargs.get('nt')
        eid_path = self._time_based_template_ids()
        eid_count = 0
        if eid_path:
            with open(eid_path, 'r', encoding='utf-8') as f:
                eid_count = sum(1 for _ in f)

        stale_days = kwargs.get('stale_days')
        self._log_banner(total, num_chunks, eid_count, stale_days)
        scan_start = time.time()
        total_findings = 0

        try:
            for i in range(0, total, self.CHUNK_SIZE):
                chunk = domain_list[i:i + self.CHUNK_SIZE]
                chunk_idx = (i // self.CHUNK_SIZE) + 1

                chunk_start = time.time()

                n_findings = self._scan_chunk(chunk, nt_option, eid_path)
                total_findings += n_findings

                chunk_secs = time.time() - chunk_start
                scanned = min(i + self.CHUNK_SIZE, total)
                elapsed = time.time() - scan_start
                avg = elapsed / scanned
                eta = (total - scanned) * avg

                self.stdout.write(
                    f'Chunk {chunk_idx}/{num_chunks}: {n_findings:,} findings in {chunk_secs:.0f}s '
                    f'({chunk_secs / len(chunk):.2f}s/asset) | '
                    f'{scanned:,}/{total:,} | ETA {eta / 60:.1f}min'
                )

            self._log_summary(total, total_findings, time.time() - scan_start)
        finally:
            if eid_path and os.path.exists(eid_path):
                try:
                    os.unlink(eid_path)
                except OSError:
                    pass

    # -------------------------------------------------------------------------
    # Domain selection (same filters as scan_nuclei.py)
    # -------------------------------------------------------------------------

    def _get_domains_to_scan(self, **kwargs):
        projectid = kwargs.get('projectid')
        scope_filter = kwargs.get('scope')
        new_assets_only = kwargs.get('new_assets')
        stale_days = kwargs.get('stale_days')

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

        if stale_days is not None:
            if stale_days <= 0:
                raise CommandError('--stale-days must be a positive integer')

            cutoff = make_aware(datetime.now()) - timedelta(days=stale_days)
            domains = domains.filter(
                Q(last_scan_time__isnull=True) | Q(last_scan_time__lt=cutoff)
            )

        return domains

    # -------------------------------------------------------------------------
    # Scan a chunk of domains
    # -------------------------------------------------------------------------

    def _scan_chunk(self, chunk, nt_option, eid_path):
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
            findings, scan_ok = self._run_nuclei(targets_path, results_path, nt_option, eid_path)

            # Persist findings
            scan_time = make_aware(datetime.now())
            self._save_findings(findings, chunk, scan_time, nt_option, scan_ok)

            # Mark assets as scanned (successful full scans only)
            if not nt_option and scan_ok:
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

    def _is_interesting(self, line):
        return (
            line.startswith(self.NUCLEI_LEVEL_TAGS)
            or line.startswith(self.NUCLEI_PANIC_PREFIXES)
            or bool(self.NUCLEI_STATS_RE.match(line))
        )

    # -------------------------------------------------------------------------
    # Run nuclei subprocess with streamed heartbeat
    # -------------------------------------------------------------------------

    def _run_nuclei(self, targets_path, results_path, nt_option, eid_path):
        """Run nuclei with optimized flags, printing only interesting output lines.

        Returns (findings, scan_ok), where scan_ok means nuclei exited successfully.
        """
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
        cmd.append('-severity')
        cmd.append(self.NUCLEI_SEVERITY)
        cmd.append('-exclude-tags')
        cmd.append(self.NUCLEI_EXCLUDE_TAGS)
        if eid_path:
            cmd.append('-eid')
            cmd.append(eid_path)

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # merge stderr → stdout for a single stream
            text=True,
            encoding='utf-8',
            errors='replace',           # avoid crash if nuclei prints non-UTF-8 (e.g. in template/finding)
            bufsize=1,                  # line-buffered
        )

        # Stream output — keep a tail buffer for failure dumps, print only
        # error/warning/panic/stats lines, collapse repeated messages.
        tail = deque(maxlen=30)
        seen_msgs = set()
        suppressed = 0
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            tail.append(line)
            if not self._is_interesting(line):
                continue
            key = self.NUCLEI_URL_RE.sub('<url>', line)
            if key in seen_msgs:
                suppressed += 1
                continue
            seen_msgs.add(key)
            self.stdout.write(f'  [nuclei] {line}')
        if suppressed:
            self.stdout.write(f'  [nuclei] (suppressed {suppressed} duplicate error lines)')

        proc.wait()

        scan_ok = proc.returncode == 0
        if not scan_ok:
            self.stderr.write(f'\n  Nuclei exited with code {proc.returncode}. CMD: {" ".join(cmd)}')
            self.stderr.write(f'  Last {len(tail)} output lines:')
            for t in tail:
                self.stderr.write(f'    | {t}')

        # Parse JSON export file — try even on non-zero exit (nuclei may have partial results)
        # Use errors='replace' so non-UTF-8 in matched content (e.g. response snippets) doesn't crash the scan
        findings = []
        if os.path.exists(results_path) and os.path.getsize(results_path) > 0:
            with open(results_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read().strip()
                if content:
                    parsed = json.loads(content)
                    if isinstance(parsed, list):
                        findings = parsed
                    else:
                        scan_ok = False
                        self.stderr.write('  Nuclei results file did not contain a JSON array; treating scan as failed.')

        if not scan_ok:
            self.stderr.write(
                f'  Nuclei failed (exit {proc.returncode}) but recovered {len(findings)} findings from partial results.'
            )

        return findings, scan_ok

    # -------------------------------------------------------------------------
    # Save findings to DB — findings are never deleted by scanners.
    #   Full successful scan → upsert results, then mark open nuclei findings
    #                          that the scan did not reproduce as 'fixed'
    #   Failed full scan     → upsert only (partial coverage proves nothing)
    #   --nt scan            → upsert only (only new templates ran)
    # -------------------------------------------------------------------------

    def _save_findings(self, findings, chunk, scan_time, nt_option, scan_ok):
        domain_map = {a.value: a for a in chunk}
        grouped = self._group_findings_by_domain(findings, domain_map)

        if not nt_option and scan_ok:
            # Successful full scan: reconcile — upsert results, then mark
            # non-reproduced open nuclei findings as fixed. Never delete.
            count = self._upsert_findings(grouped, scan_time)
            fixed = self._mark_absent_findings(chunk, scan_time, source='nuclei')
            self.stdout.write(f'  Saved {count:,} findings | {fixed} marked fixed (no deletions)')
        elif not findings:
            return
        else:
            # --nt and failed full scans preserve existing findings (partial
            # coverage proves nothing: absence must NOT mark fixed).
            count = self._upsert_findings(grouped, scan_time)
            label = '--nt scan' if nt_option else 'partial scan'
            self.stdout.write(f'  Saved {count:,} findings from {label} (get_or_create)')

    def _mark_absent_findings(self, chunk, scan_time, source):
        """Mark open findings of `source` on these assets as fixed.

        Only safe when the run's template set fully covered detection
        (successful full scans): _upsert_findings just wrote scan_date=scan_time
        for every reproduced finding, so open rows still carrying an older
        scan_date were not seen and count as fixed. Rows are never deleted.
        """
        objs = list(Finding.objects.filter(
            asset__in=chunk,
            source=source,
            ignore=False,
            status=Finding.STATUS_OPEN,
        ).exclude(scan_date=scan_time))
        for obj in objs:
            obj.status = Finding.STATUS_FIXED
            obj.fixed_date = scan_time
        if objs:
            Finding.objects.bulk_update(
                objs, ['status', 'fixed_date'], batch_size=self.DB_BATCH_SIZE)
        return len(objs)

    def _upsert_findings(self, grouped, scan_time):
        """Insert or update findings without deleting existing ones."""
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
                if data.get('template_id'):
                    obj.template_id = data['template_id']
                if obj.status == Finding.STATUS_FIXED:
                    # Regression: a previously fixed finding was re-detected.
                    obj.status = Finding.STATUS_OPEN
                    obj.fixed_date = None
                obj.save()
                count += 1
        return count

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
        # matched-at is the exact endpoint (path included); url is only scheme://host[:port]
        url = finding.get('matched-at', '') or finding.get('url', '')

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
            description = f'URL: {url}\n\n{description}' if description else f'URL: {url}'

        return {
            'asset': domain,
            'asset_name': domain.value,
            'source': 'nuclei',
            'name': info.get('name', 'Unknown'),
            'type': finding.get('type', ''),
            'url': url,
            'template_id': finding.get('template-id', ''),
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

    # -------------------------------------------------------------------------
    # --check mode: re-probe open nuclei findings with their recorded template
    # -------------------------------------------------------------------------

    def _check_findings(self, **kwargs):
        """Re-probe open nuclei findings with the exact template that found them.

        Each finding is re-tested by re-running its stored template_id against
        its stored URL — never a full rescan of the target. Reproduced findings
        stay open with scan_date/last_seen refreshed; findings not reproduced by
        a successful probe run are marked fixed. Findings whose template run
        fails stay open (a failed probe proves nothing). No inserts, no deletes,
        and Asset.last_scan_time stays untouched (a probe run is not a scan).
        """
        raw_sev = kwargs.get('check_severity') or 'high,critical'
        sevs = [s.strip().lower() for s in raw_sev.split(',') if s.strip()]
        if not sevs:
            raise CommandError('--check-severity must list at least one severity')

        findings = Finding.objects.filter(
            source='nuclei',
            ignore=False,
            status=Finding.STATUS_OPEN,
            severity__in=sevs,
            asset__monitor=True,
            asset__ignore=False,
        )

        projectid = kwargs.get('projectid')
        if projectid:
            try:
                project = Project.objects.get(id=projectid)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
            findings = findings.filter(asset__related_project=project)

        scope_filter = kwargs.get('scope')
        if scope_filter:
            findings = findings.filter(asset__scope__iexact=scope_filter)

        uuid_list = resolve_uuids(kwargs)
        if uuid_list:
            findings = findings.filter(asset__uuid__in=uuid_list)

        legacy = findings.filter(template_id='').count()
        if legacy:
            self.stdout.write(
                f'[i] {legacy} open findings have no template_id and cannot be re-probed '
                f'(they update on the next full nuclei scan)'
            )
        findings = findings.exclude(template_id='')

        by_template = {}
        for f in findings.iterator(chunk_size=1000):
            by_template.setdefault(f.template_id, []).append(f)

        check_time = make_aware(datetime.now())
        probed = present = fixed = failed_runs = 0

        for template_id, items in sorted(by_template.items()):
            for i in range(0, len(items), self.CHUNK_SIZE):
                batch = items[i:i + self.CHUNK_SIZE]
                urls = sorted({f.url for f in batch if f.url})
                if not urls:
                    continue
                targets_path = None
                try:
                    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tf:
                        targets_path = tf.name
                        for url in urls:
                            tf.write(f'{url}\n')

                    results, ok = self._run_nuclei_for_template(template_id, targets_path)
                    if not ok:
                        failed_runs += 1
                        continue

                    # The probe re-runs the recorded template against the recorded
                    # matched-at URL, so any reproduction returns that same URL.
                    seen = {
                        (r.get('template-id', ''), r.get('matched-at') or r.get('url', ''))
                        for r in results
                    }
                    still_present, now_fixed = [], []
                    for f in batch:
                        if (f.template_id, f.url) in seen:
                            f.scan_date = check_time
                            f.last_seen = check_time
                            still_present.append(f)
                        else:
                            f.status = Finding.STATUS_FIXED
                            f.fixed_date = check_time
                            now_fixed.append(f)

                    if still_present:
                        Finding.objects.bulk_update(
                            still_present, ['scan_date', 'last_seen'], batch_size=self.DB_BATCH_SIZE)
                    if now_fixed:
                        Finding.objects.bulk_update(
                            now_fixed, ['status', 'fixed_date'], batch_size=self.DB_BATCH_SIZE)

                    probed += len(batch)
                    present += len(still_present)
                    fixed += len(now_fixed)
                except Exception as e:
                    self.stderr.write(f'  ERROR checking template {template_id}: {e}')
                finally:
                    if targets_path and os.path.exists(targets_path):
                        try:
                            os.unlink(targets_path)
                        except OSError:
                            pass

        self.stdout.write(
            f'CHECK COMPLETE: {probed:,} findings probed across {len(by_template):,} templates | '
            f'{present:,} still present | {fixed:,} marked fixed | {failed_runs} template runs failed'
        )

    def _run_nuclei_for_template(self, template_id, targets_path):
        """Run one nuclei template (nuclei -id <template-id>) against a URL list.

        Deliberately minimal: only the recorded template runs against the
        recorded URLs — no full template set, no -severity, no -exclude-tags,
        no -ss. Returns (results, ok). On any nuclei failure ok=False (and an
        empty result list); the caller must then leave findings untouched so a
        missing/renamed template never produces false fixes.
        """
        results_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as rf:
                results_path = rf.name

            cmd = [
                'nuclei',
                '-id', template_id,
                '-l', targets_path,
                '-je', results_path,
                '-c', '25',
                '-rl', str(self.NUCLEI_RATE_LIMIT),
                '-timeout', str(self.NUCLEI_TIMEOUT),
                '-retries', str(self.NUCLEI_RETRIES),
                '-duc',
                '-nc',
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if proc.returncode != 0:
                self.stderr.write(
                    f'  [skip] template {template_id} run failed (exit {proc.returncode}); '
                    f'findings left open'
                )
                return [], False

            results = []
            if os.path.exists(results_path) and os.path.getsize(results_path) > 0:
                with open(results_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().strip()
                    if content:
                        parsed = json.loads(content)
                        if isinstance(parsed, list):
                            results = parsed
                        else:
                            self.stderr.write(
                                f'  [skip] template {template_id} results file held no JSON array; '
                                f'findings left open'
                            )
                            return [], False
            return results, True
        finally:
            if results_path and os.path.exists(results_path):
                try:
                    os.unlink(results_path)
                except OSError:
                    pass

    def _time_based_template_ids(self):
        """Write IDs of time-based (duration) templates to a temp file; return its path.

        The file is handed to nuclei via -eid so response-delay templates never run.
        Returns None (with a warning) when NUCLEI_TEMPLATES is unset or missing.
        """
        tpl_dir = getattr(settings, 'NUCLEI_TEMPLATES', '')
        if not tpl_dir:
            self.stdout.write(
                '  [i] NUCLEI_TEMPLATES not set in settings; skipping time-based template exclusion.'
            )
            return None

        tpl_dir = os.path.expanduser(tpl_dir)
        if not os.path.isdir(tpl_dir):
            self.stdout.write(f'  [i] NUCLEI_TEMPLATES dir not found: {tpl_dir}')
            return None

        ids = set()
        id_re = re.compile(r'^id:\s*(\S+)')
        for root, _dirs, files in os.walk(tpl_dir):
            for fname in files:
                if not fname.endswith('.yaml'):
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, 'r', encoding='utf-8', errors='replace') as f:
                        text = f.read()
                except OSError:
                    continue
                if 'duration' not in text:
                    continue
                m = id_re.search(text)
                if m:
                    ids.add(m.group(1))

        if not ids:
            return None

        f = tempfile.NamedTemporaryFile(delete=False, suffix='.txt', mode='w', encoding='utf-8')
        try:
            f.write('\n'.join(sorted(ids)))
        finally:
            f.close()
        return f.name

    def _log_banner(self, total, num_chunks, eid_count, stale_days=None):
        filters = (
            f'severity {self.NUCLEI_SEVERITY} | '
            f'exclude-tags {self.NUCLEI_EXCLUDE_TAGS} | '
            f'time-based templates excluded: {eid_count or "none"}'
        )
        if stale_days:
            filters += f' | stale-days {stale_days}'

        self.stdout.write(
            f'NUCLEI SCAN: {total:,} assets | {num_chunks} chunks x {self.CHUNK_SIZE:,} | {filters}'
        )

    def _log_summary(self, total, total_findings, total_secs):
        self.stdout.write(
            f'SCAN COMPLETE: {total:,} assets | {total_findings:,} findings | '
            f'{total_secs / 60:.1f} min | {total_secs / total:.2f}s/asset'
        )

    def update_nuclei(self):
        """Update Nuclei engine and templates."""
        for flag, label in [('-up', 'engine'), ('-ut', 'templates')]:
            result = subprocess.run(['nuclei', flag], capture_output=True, text=True)
            if result.returncode != 0:
                self.stderr.write(f'Error updating {label}: {result.stderr}')
                return
        self.stdout.write("Nuclei engine and templates updated.")
