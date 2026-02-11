import json
import time

import requests
from urllib.parse import urlparse

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Run Burp Suite scan against a specific URL using the local Burp Suite REST API'

    def add_arguments(self, parser):
        parser.add_argument(
            'url',
            type=str,
            help='URL to scan (e.g., https://example.com)',
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
            '--api-key',
            type=str,
            help='Burp Suite API key (if authentication is enabled)',
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

    def handle(self, *args, **options):
        url = options['url']
        burp_host = options['burp_host']
        burp_port = options['burp_port']
        api_key = options.get('api_key')
        scan_config = options['scan_config']
        wait_for_completion = options['wait']
        timeout = options['timeout']

        self._validate_url(url)

        burp_api_base = f"http://{burp_host}:{burp_port}"
        headers = self._build_headers(api_key)

        self.stdout.write(f"Starting Burp Suite scan for: {url}")
        self.stdout.write(f"Using Burp API at: {burp_api_base}")

        try:
            self._test_connection(burp_api_base, headers)

            task_id = self._start_scan(burp_api_base, headers, url, scan_config)

            if task_id:
                self.stdout.write(self.style.SUCCESS(f"Scan started successfully! Task ID: {task_id}"))

                if wait_for_completion:
                    self._wait_for_scan(burp_api_base, headers, task_id, timeout)
                else:
                    self.stdout.write("Use --wait flag to monitor scan progress")
                    self.stdout.write(f"Check scan status manually with task ID: {task_id}")
            else:
                self.stdout.write(self.style.SUCCESS("Scan started (no task ID returned by API)"))

        except CommandError:
            raise
        except Exception as e:
            raise CommandError(f"Failed to start Burp Suite scan: {e}")

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
    def _build_headers(api_key=None):
        """Return common request headers, optionally including an API key."""
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        return headers

    def _test_connection(self, base_url, headers):
        """Verify the Burp Suite REST API is reachable."""
        try:
            response = requests.get(f"{base_url}/v0.1/", headers=headers, timeout=10)
            response.raise_for_status()
            self.stdout.write("Connected to Burp Suite API successfully")
        except requests.exceptions.ConnectionError:
            raise CommandError(
                "Cannot connect to Burp Suite API. "
                "Make sure Burp Suite is running with the REST API enabled."
            )
        except requests.exceptions.Timeout:
            raise CommandError("Connection to Burp Suite API timed out")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise CommandError("Authentication failed. Check your API key.")
            raise CommandError(f"HTTP error from Burp Suite API: {e}")

    def _start_scan(self, base_url, headers, url, scan_config):
        """Start a Burp Suite scan and return the task ID (or None)."""
        scan_data = {
            "urls": [url],
            "scan_configurations": [
                {
                    "name": scan_config,
                    "type": "NamedConfiguration",
                }
            ],
        }

        response = requests.post(
            f"{base_url}/v0.1/scan",
            headers=headers,
            json=scan_data,
            timeout=30,
        )

        if response.status_code == 201:
            # The Burp REST API returns the task ID as a plain integer in the body.
            task_id = response.text.strip()
            return task_id if task_id else None

        response.raise_for_status()

    def _wait_for_scan(self, base_url, headers, task_id, timeout):
        """Poll until the scan finishes (or *timeout* seconds elapse), then show results."""
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
                status_response = requests.get(
                    f"{base_url}/v0.1/scan/{task_id}",
                    headers=headers,
                    timeout=10,
                )

                if status_response.status_code == 200:
                    scan_status = self._parse_scan_status(status_response)
                    self.stdout.write(f"Scan status: {scan_status}")

                    if scan_status in ('succeeded', 'failed', 'cancelled'):
                        break

                elif status_response.status_code == 404:
                    self.stdout.write(
                        self.style.WARNING("Scan task not found. It may have completed or been removed.")
                    )
                    break

            except requests.exceptions.RequestException as e:
                self.stdout.write(self.style.WARNING(f"Error checking scan status: {e}"))

            time.sleep(poll_interval)

        self._display_results(base_url, headers, task_id)

    def _parse_scan_status(self, response):
        """Extract scan_status from a status response, returning 'unknown' on failure."""
        try:
            return response.json().get('scan_status', 'unknown')
        except (json.JSONDecodeError, ValueError):
            self.stdout.write(
                self.style.WARNING(f"Invalid JSON in status response: {response.text[:200]}")
            )
            return 'unknown'

    def _display_results(self, base_url, headers, task_id):
        """Fetch and display issues found during the scan."""
        try:
            response = requests.get(
                f"{base_url}/v0.1/scan/{task_id}",
                headers=headers,
                timeout=30,
            )
        except requests.exceptions.RequestException as e:
            self.stdout.write(self.style.WARNING(f"Error retrieving scan results: {e}"))
            return

        if response.status_code != 200:
            self.stdout.write(self.style.WARNING("Could not retrieve scan results."))
            return

        try:
            data = response.json()
        except (json.JSONDecodeError, ValueError):
            self.stdout.write(self.style.WARNING("Invalid JSON in scan results response."))
            return

        issues = data.get('issue_events', [])

        if not issues:
            self.stdout.write(self.style.SUCCESS("Scan completed! No issues found."))
            return

        self.stdout.write(self.style.SUCCESS(f"\nScan completed! Found {len(issues)} issue(s):"))

        for event in issues:
            issue = event.get('issue', event)
            severity = issue.get('severity', 'Unknown')
            confidence = issue.get('confidence', 'Unknown')
            name = issue.get('name', 'Unknown Issue')
            origin = issue.get('origin', 'Unknown URL')
            path = issue.get('path', '')

            style = self._severity_style(severity)
            self.stdout.write(style(f"  [{severity}] {name} - {origin}{path}"))
            self.stdout.write(f"    Confidence: {confidence}")

    def _severity_style(self, severity):
        """Return the appropriate output style for a given severity level."""
        severity_lower = severity.lower()
        if severity_lower == 'high':
            return self.style.ERROR
        if severity_lower == 'medium':
            return self.style.WARNING
        return self.style.NOTICE
