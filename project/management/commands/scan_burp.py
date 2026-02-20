import json
import os
import re
import time
import requests
from urllib.parse import urlparse
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.utils.timezone import now
from findings.models import Finding, Endpoint
from project.models import Asset


class Command(BaseCommand):
    help = 'Run Burp Suite scan against one or more URLs using the local Burp Suite REST API'

    def add_arguments(self, parser):
        parser.add_argument(
            'urls',
            nargs='*',
            type=str,
            help='One or more URLs to scan (e.g., https://example.com https://other.com)',
        )
        parser.add_argument(
            '--burp-host',
            type=str,
            default='127.0.0.1',
            help='Burp Suite API host (default: 127.0.0.1)',
        )
        parser.add_argument(
            '--burp-port',
            type=int,
            default=1337,
            help='Burp Suite API port (default: 1337)',
        )
        parser.add_argument(
            '--scan-config',
            type=str,
            default='Audit coverage - maximum',
            help='Burp Suite scan configuration name (default: "Audit coverage - maximum")',
        )
        parser.add_argument(
            '--wait',
            action='store_true',
            help='Wait for scan completion and show results',
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=3600,
            help='Maximum time to wait for scan completion in seconds (default: 3600)',
        )
        parser.add_argument(
            '--urls-file',
            type=str,
            default=None,
            help='Read target URLs from a JSON file (a list like ["https://...", ...]) instead of positional args',
        )
        parser.add_argument(
            '--from-file',
            type=str,
            default=None,
            help='Import findings from a saved Burp JSON results file (skips live scan)',
        )
        parser.add_argument(
            '--save-response',
            type=str,
            default=None,
            help='Save the raw Burp API JSON response to this file path',
        )

    def handle(self, *args, **options):
        from_file = options['from_file']

        # --from-file mode: skip the live scan entirely
        if from_file:
            self.stdout.write(f"Importing Burp findings from file: {from_file}")
            try:
                with open(from_file, 'r') as f:
                    data = json.load(f)
            except FileNotFoundError:
                raise CommandError(f"File not found: {from_file}")
            except json.JSONDecodeError as e:
                raise CommandError(f"Invalid JSON in file {from_file}: {e}")

            self._import_findings(data)
            return

        # Live scan mode: resolve URLs from positional args or --urls-file
        urls = options['urls']
        urls_file = options['urls_file']

        if urls_file:
            try:
                with open(urls_file, 'r') as f:
                    urls = json.load(f)
            except FileNotFoundError:
                raise CommandError(f"URLs file not found: {urls_file}")
            except json.JSONDecodeError as e:
                raise CommandError(f"Invalid JSON in URLs file {urls_file}: {e}")
            if not isinstance(urls, list) or not urls:
                raise CommandError(f"URLs file must contain a non-empty JSON array of URL strings.")

        if not urls:
            raise CommandError("You must provide at least one URL, use --urls-file, or use --from-file to import.")

        burp_host = options['burp_host']
        burp_port = options['burp_port']
        api_key = settings.BURP_API_KEY
        scan_config = options['scan_config']
        wait_for_completion = options['wait']
        timeout = options['timeout']
        save_response = options['save_response']

        for url in urls:
            self._validate_url(url)

        burp_api_base = f"http://{burp_host}:{burp_port}"
        headers = self._build_headers()

        self.stdout.write(f"Starting Burp Suite scan for {len(urls)} URL(s):")
        for url in urls:
            self.stdout.write(f"  - {url}")
        self.stdout.write(f"Using Burp API at: {burp_api_base}")
        self.stdout.write(f"API key configured: {'Yes' if api_key else 'No'}")

        try:
            self._test_connection(burp_api_base, api_key, headers)

            task_id = self._start_scan(burp_api_base, api_key, headers, urls, scan_config)

            if task_id:
                self.stdout.write(self.style.SUCCESS(f"Scan started successfully! Task ID: {task_id}"))

                if wait_for_completion:
                    self._wait_for_scan(burp_api_base, api_key, headers, task_id, timeout, save_response)
                else:
                    self.stdout.write("Use --wait flag to monitor scan progress")
                    self.stdout.write(f"Check scan status manually with task ID: {task_id}")
            else:
                raise CommandError(
                    "Scan request was accepted but no task ID could be extracted. "
                    "Check the verbose output above for response details."
                )

        except CommandError:
            raise
        except Exception as e:
            raise CommandError(f"Failed to start Burp Suite scan: {e}")
        finally:
            # Clean up the temporary URLs file if one was used
            if urls_file:
                try:
                    os.remove(urls_file)
                    self.stdout.write(f"Cleaned up URLs file: {urls_file}")
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_url(url):
        """Raise CommandError if *url* is not a valid HTTP(S) URL."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise CommandError(f"Invalid URL '{url}': must include scheme and host (e.g. https://example.com)")

    @staticmethod
    def _build_headers():
        """Return common request headers."""
        return {'Content-Type': 'application/json'}

    @staticmethod
    def _build_api_url(base_url, api_key, endpoint):
        """Build a Burp REST API URL with the API key embedded in the path."""
        if api_key:
            return f"{base_url}/{api_key}/v0.1/{endpoint}"
        return f"{base_url}/v0.1/{endpoint}"

    def _redact_api_key(self, text, api_key):
        """Replace the API key in text with a redacted placeholder for safe logging."""
        if api_key and api_key in text:
            return text.replace(api_key, "<API_KEY>")
        return text

    def _log_response(self, label, response, api_key):
        """Log detailed response information for debugging."""
        self.stdout.write(f"  [{label}] Status: {response.status_code} {response.reason}")
        for key, value in response.headers.items():
            safe_value = self._redact_api_key(value, api_key)
            self.stdout.write(f"  [{label}] Header: {key}: {safe_value}")
        body = response.text[:500] if response.text else "<empty>"
        self.stdout.write(f"  [{label}] Body: {body}")

    def _test_connection(self, base_url, api_key, headers):
        """Verify the Burp Suite REST API is reachable."""
        url = self._build_api_url(base_url, api_key, "")
        safe_url = self._redact_api_key(url, api_key)
        self.stdout.write(f"Testing connection: GET {safe_url}")

        try:
            response = requests.get(url, headers=headers, timeout=10)
        except requests.exceptions.ConnectionError as e:
            raise CommandError(
                f"Cannot connect to Burp Suite API at {base_url}. "
                f"Make sure Burp Suite is running with the REST API enabled.\n"
                f"Connection error: {e}"
            )
        except requests.exceptions.Timeout:
            raise CommandError(f"Connection to Burp Suite API timed out after 10s")

        self._log_response("connection-test", response, api_key)

        if response.status_code == 401:
            raise CommandError(
                f"Authentication failed (HTTP 401). Response: {response.text}\n"
                "Check your BURP_API_KEY in settings."
            )

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise CommandError(f"HTTP error from Burp Suite API: {e}\nBody: {response.text[:500]}")

        self.stdout.write(self.style.SUCCESS("Connected to Burp Suite API successfully"))

    def _extract_task_id(self, response, api_key):
        """
        Extract the task ID from the scan response.

        The Burp REST API can return the task ID in multiple ways:
        1. Location header (e.g. "/{api_key}/v0.1/scan/{task_id}" or "/v0.1/scan/{task_id}")
        2. Response body as a plain integer
        3. Response body as JSON with a task_id field
        """
        task_id = None

        # 1. Try Location header
        location = response.headers.get('Location', '').strip()
        if location:
            self.stdout.write(f"  Location header found: {self._redact_api_key(location, api_key)}")
            # Match a bare integer or the last numeric segment of a path
            match = re.search(r'(?:^|/)(\d+)$', location)
            if match:
                task_id = match.group(1)
                self.stdout.write(f"  Task ID from Location header: {task_id}")
                return task_id

        # 2. Try response body as plain integer
        body = response.text.strip()
        if body and body.isdigit():
            task_id = body
            self.stdout.write(f"  Task ID from response body (plain integer): {task_id}")
            return task_id

        # 3. Try response body as JSON
        if body:
            try:
                data = response.json()
                if isinstance(data, dict):
                    task_id = data.get('task_id') or data.get('id') or data.get('scan_id')
                    if task_id:
                        self.stdout.write(f"  Task ID from JSON body: {task_id}")
                        return str(task_id)
                elif isinstance(data, (int, str)):
                    task_id = str(data)
                    self.stdout.write(f"  Task ID from JSON body (scalar): {task_id}")
                    return task_id
            except (json.JSONDecodeError, ValueError):
                pass

        self.stdout.write(self.style.WARNING("  Could not extract task ID from response"))
        return None

    def _start_scan(self, base_url, api_key, headers, urls, scan_config):
        """Start a Burp Suite scan and return the task ID (or None)."""
        scan_url = self._build_api_url(base_url, api_key, "scan")
        safe_url = self._redact_api_key(scan_url, api_key)

        scan_data = {
            "urls": urls,
            "scan_configurations": [
                {
                    "name": scan_config,
                    "type": "NamedConfiguration",
                }
            ],
        }

        self.stdout.write(f"Sending scan request: POST {safe_url}")
        self.stdout.write(f"  Payload: {json.dumps(scan_data, indent=2)}")

        try:
            response = requests.post(
                scan_url,
                headers=headers,
                json=scan_data,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            raise CommandError(f"Failed to send scan request: {e}")

        self._log_response("start-scan", response, api_key)

        if response.status_code in (200, 201):
            return self._extract_task_id(response, api_key)

        # Non-success status
        raise CommandError(
            f"Scan request failed with HTTP {response.status_code} {response.reason}.\n"
            f"Response body: {response.text[:500]}"
        )

    def _wait_for_scan(self, base_url, api_key, headers, task_id, timeout, save_response=None):
        """Poll until the scan finishes (or *timeout* seconds elapse), then fetch and import results."""
        self.stdout.write("Waiting for scan completion...")
        start_time = time.time()
        poll_interval = 10  # seconds

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                self.stdout.write(
                    self.style.WARNING(f"Timeout reached ({timeout}s). Scan may still be running.")
                )
                break

            try:
                status_url = self._build_api_url(base_url, api_key, f"scan/{task_id}")
                status_response = requests.get(status_url, headers=headers, timeout=10)

                if status_response.status_code == 200:
                    scan_status = self._parse_scan_status(status_response)
                    self.stdout.write(
                        f"  [{int(elapsed)}s] Scan status: {scan_status}"
                    )

                    if scan_status in ('succeeded', 'failed', 'cancelled'):
                        break

                elif status_response.status_code == 404:
                    self.stdout.write(
                        self.style.WARNING("Scan task not found. It may have completed or been removed.")
                    )
                    break
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f"  Unexpected status polling response: "
                            f"HTTP {status_response.status_code} - {status_response.text[:200]}"
                        )
                    )

            except requests.exceptions.RequestException as e:
                self.stdout.write(self.style.WARNING(f"Error checking scan status: {e}"))

            time.sleep(poll_interval)

        self._fetch_and_import_results(base_url, api_key, headers, task_id, save_response)

    def _parse_scan_status(self, response):
        """Extract scan_status from a status response, returning 'unknown' on failure."""
        try:
            return response.json().get('scan_status', 'unknown')
        except (json.JSONDecodeError, ValueError):
            self.stdout.write(
                self.style.WARNING(f"Invalid JSON in status response: {response.text[:200]}")
            )
            return 'unknown'

    def _fetch_and_import_results(self, base_url, api_key, headers, task_id, save_response=None):
        """Fetch scan results from the API, optionally save to file, and import as findings."""
        results_url = self._build_api_url(base_url, api_key, f"scan/{task_id}")
        safe_url = self._redact_api_key(results_url, api_key)
        self.stdout.write(f"Fetching results: GET {safe_url}")

        try:
            response = requests.get(results_url, headers=headers, timeout=30)
        except requests.exceptions.RequestException as e:
            self.stdout.write(self.style.WARNING(f"Error retrieving scan results: {e}"))
            return

        if response.status_code != 200:
            self.stdout.write(
                self.style.WARNING(
                    f"Could not retrieve scan results: HTTP {response.status_code} - {response.text[:200]}"
                )
            )
            return

        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            self.stdout.write(self.style.WARNING("Invalid JSON in scan results response."))
            return

        # Save raw response to file if requested
        if save_response:
            try:
                with open(save_response, 'w') as f:
                    json.dump(data, f, indent=2)
                self.stdout.write(self.style.SUCCESS(f"Raw API response saved to: {save_response}"))
            except OSError as e:
                self.stdout.write(self.style.WARNING(f"Could not save response to file: {e}"))

        self._import_findings(data)

    # ------------------------------------------------------------------
    # Finding import
    # ------------------------------------------------------------------

    def _resolve_asset(self, origin, path):
        """
        Try to find an Asset for the given Burp issue origin + path.

        Strategy:
        1. Look up a matching Endpoint by URL prefix and get its linked Asset.
        2. Fall back to looking up an Asset whose value matches the origin hostname.
        Returns the Asset or None.
        """
        full_url = f"{origin}{path}" if path else origin

        # 1. Try exact Endpoint match (origin + path)
        try:
            endpoint = Endpoint.objects.filter(url=full_url).select_related('asset').first()
            if endpoint and endpoint.asset:
                return endpoint.asset
        except Exception:
            pass

        # 2. Try matching by origin only (without path)
        try:
            endpoint = Endpoint.objects.filter(url__startswith=origin).select_related('asset').first()
            if endpoint and endpoint.asset:
                return endpoint.asset
        except Exception:
            pass

        # 3. Fall back to Asset lookup by hostname
        parsed = urlparse(origin)
        hostname = parsed.hostname or ''
        if hostname:
            asset = Asset.objects.filter(value=hostname).first()
            if asset:
                return asset

        return None

    def _import_findings(self, data):
        """Parse Burp issue_events and create/update Finding objects."""
        issues = data.get('issue_events', [])

        if not issues:
            self.stdout.write(self.style.SUCCESS("No issues found in Burp results."))
            return

        self.stdout.write(f"Processing {len(issues)} issue(s) from Burp results...")

        scan_time = now()
        created_count = 0
        updated_count = 0
        skipped_count = 0

        for event in issues:
            issue = event.get('issue', event)

            name = issue.get('name', 'Unknown Issue')
            severity = (issue.get('severity') or 'info').lower()
            confidence = issue.get('confidence', 'Unknown')
            origin = issue.get('origin', '')
            path = issue.get('path', '')
            full_url = f"{origin}{path}" if path else origin
            type_index = str(issue.get('type_index', ''))
            description = issue.get('description', '') or issue.get('description_html', '')
            remediation = issue.get('remediation', '') or issue.get('remediation_html', '')

            # Resolve asset
            asset = self._resolve_asset(origin, path)
            if not asset:
                self.stdout.write(
                    self.style.WARNING(f"  Skipped (no matching asset): [{severity}] {name} - {full_url}")
                )
                skipped_count += 1
                continue

            # Dedup lookup fields
            lookup = {
                'asset': asset,
                'source': 'burp',
                'name': name,
                'url': full_url,
            }

            defaults = {
                'asset_name': asset.value,
                # 'type': type_index,
                'severity': severity,
                'description': description,
                'solution': remediation,
                'vulnerabilityDetails': f"Confidence: {confidence}",
                'scan_date': scan_time,
                'raw': issue,
            }

            obj, created = Finding.objects.get_or_create(**lookup, defaults=defaults)

            if created:
                created_count += 1
                style = self._severity_style(severity)
                self.stdout.write(style(f"  [NEW] [{severity}] {name} - {full_url}"))
            else:
                # Update mutable fields on re-import
                obj.severity = severity
                obj.description = description
                obj.solution = remediation
                obj.vulnerabilityDetails = f"Confidence: {confidence}"
                obj.scan_date = scan_time
                obj.raw = issue
                obj.save()
                updated_count += 1
                self.stdout.write(f"  [UPDATED] [{severity}] {name} - {full_url}")

        self.stdout.write(
            self.style.SUCCESS(
                f"\nImport complete: {created_count} new, {updated_count} updated, {skipped_count} skipped (no asset)."
            )
        )

    def _severity_style(self, severity):
        """Return the appropriate output style for a given severity level."""
        severity_lower = severity.lower()
        if severity_lower == 'high':
            return self.style.ERROR
        if severity_lower == 'medium':
            return self.style.WARNING
        return self.style.NOTICE
