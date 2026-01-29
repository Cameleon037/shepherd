import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import Asset, Project
from findings.models import Screenshot
from django.conf import settings
import tempfile


class Command(BaseCommand):
    help = 'Run Httpx scan against http endpoints'

    def add_arguments(self, parser):
        # Add an optional projectid argument
        parser.add_argument(
            '--projectid',
            type=int,
            help='ID of the project to scan',
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
        parser.add_argument(
            '--missing-screenshots',
            action='store_true',
            help='Only scan assets (domains) where Screenshot.screenshot_base64 is empty',
        )

    def handle(self, *args, **options):
        projectid = options.get('projectid')
        uuids_arg = options.get('uuids')
        scope_filter = options.get('scope')
        new_assets_only = options.get('new_assets')
        missing_screenshots = options.get('missing_screenshots')

        if missing_screenshots:
            # Get all Screenshot objects with empty screenshot_base64 and non-null domain
            screenshot_qs = Screenshot.objects.filter(screenshot_base64='').exclude(domain=None)
            # Get unique domain IDs from these screenshots
            domain_ids = screenshot_qs.values_list('domain_id', flat=True).distinct()
            active_domains = Asset.objects.filter(uuid__in=domain_ids, monitor=True)
            if projectid:
                active_domains = active_domains.filter(related_project_id=projectid)
            if uuids_arg:
                uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
                active_domains = active_domains.filter(uuid__in=uuid_list)
            if scope_filter:
                active_domains = active_domains.filter(scope=scope_filter)
        else:
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

        httpx_urls = []
        for active_domain in active_domains:
            active_domain_urls = []
            ports = active_domain.port_set.all()
            self.stdout.write(f"Active Domain: {active_domain.value}")
            for port in ports:
                if "https" in port.banner:
                    url = f"https://{active_domain.value}:{port.port}"
                    active_domain_urls.append(url)
                elif "http" in port.banner:
                    active_domain_urls += [
                        f"http://{active_domain.value}:{port.port}",
                        f"https://{active_domain.value}:{port.port}",
                    ]
                elif "ssl" in port.banner:
                    active_domain_urls += [
                        f"https://{active_domain.value}:{port.port}",
                    ]
            active_domain_urls = list(set(active_domain_urls))
            for url in active_domain_urls:
                self.stdout.write(f"  {url}")
            
            httpx_urls += active_domain_urls

        self.stdout.write(f"Total URLs: {len(httpx_urls)}")
        
        # Split URLs into chunks of 20
        chunk_size = 20
        url_chunks = [httpx_urls[i:i + chunk_size] for i in range(0, len(httpx_urls), chunk_size)]
        self.stdout.write(f"Processing {len(url_chunks)} chunk(s) of up to {chunk_size} URLs each")

        def process_httpx_chunk(chunk_index, url_chunk):
            """Process a single chunk of URLs with httpx"""
            httpx_path = settings.HTTPX_PATH
            
            # Use tempfile for input and output files for this chunk
            with tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=f'_chunk_{chunk_index}_in.txt') as in_f, tempfile.NamedTemporaryFile(mode='w+', delete=True, suffix=f'_chunk_{chunk_index}_out.json') as out_f:
                
                httpx_in_file = in_f.name
                httpx_out_file = out_f.name
                
                # Write URLs to input file
                for url in url_chunk:
                    in_f.write(f"{url}\n")
                in_f.flush()

                self.stdout.write(f"Chunk {chunk_index + 1}: Processing {len(url_chunk)} URLs")

                command = [
                    httpx_path,
                    "-l", httpx_in_file,
                    "-ss",
                    "-st", "60",
                    "-no-screenshot-full-page",
                    "-td",
                    "-j",
                    "-o", httpx_out_file,
                ]

                try:
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/tmp/", check=True, text=True)
                    self.stdout.write(f"Chunk {chunk_index + 1}: Httpx scan completed successfully.")
                except subprocess.CalledProcessError as e:
                    self.stdout.write(f"Chunk {chunk_index + 1}: Error occurred while running Httpx (exit code {e.returncode}):")
                    if e.stderr:
                        self.stdout.write(f"STDERR: {e.stderr}")
                    if e.stdout:
                        self.stdout.write(f"STDOUT: {e.stdout}")
                    return []
                except Exception as e:
                    self.stdout.write(f"Chunk {chunk_index + 1}: Unexpected error running Httpx: {e}")
                    return []

                # Process results from this chunk
                results = []
                try:
                    with open(httpx_out_file, 'r') as f:
                        for line in f:
                            if line.strip():  # Skip empty lines
                                try:
                                    screenshot_json = json.loads(line)
                                    results.append(screenshot_json)
                                except json.JSONDecodeError as e:
                                    self.stdout.write(f"Chunk {chunk_index + 1}: Error parsing JSON line: {e}")
                                    continue
                except FileNotFoundError:
                    self.stdout.write(f"Chunk {chunk_index + 1}: Output file not found")
                
                self.stdout.write(f"Chunk {chunk_index + 1}: Processed {len(results)} results")
                return results

        # Process chunks in parallel using ThreadPoolExecutor
        all_results = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            # Submit all chunks for processing
            futures = [executor.submit(process_httpx_chunk, i, chunk) for i, chunk in enumerate(url_chunks)]
            
            # Collect results as they complete
            for future in as_completed(futures):
                try:
                    chunk_results = future.result()
                    all_results.extend(chunk_results)
                except Exception as e:
                    self.stdout.write(f"Error processing chunk: {e}")

        self.stdout.write(f"Total results collected: {len(all_results)}")

        # Store all results in the DB
        for screenshot_json in all_results:
            # Fields available:
            #     timestamp
            #     port
            #     url !
            #     input
            #     location
            #     title !
            #     scheme
            #     webserver !
            #     content_type
            #     method
            #     host !
            #     path
            #     time
            #     a
            #     tech !
            #     words
            #     lines
            #     status_code !
            #     content_length
            #     failed !
            #     headless_body !
            #     screenshot_bytes !
            #     stored_response_path
            #     screenshot_path
            #     screenshot_path_rel
            #     knowledgebase
            #     resolvers
            
            # Extract domain from url and match to Asset
            parsed_url = urlparse(screenshot_json["url"])
            domain_value = parsed_url.hostname
            domain_obj = None
            if domain_value:
                domain_obj = Asset.objects.filter(value__iexact=domain_value).first()
                
            screenshot_defaults = {
                "domain": domain_obj,
                "technologies": ",".join(screenshot_json.get("tech", [])),
                "screenshot_base64": screenshot_json.get("screenshot_bytes", ""),
                "title": screenshot_json.get("title", ""),
                "webserver": screenshot_json.get("webserver", ""),
                "host_ip": screenshot_json.get("host", ""),
                "status_code": screenshot_json.get("status_code", None),
                "response_body": screenshot_json.get("headless_body", ""),
                "failed": screenshot_json.get("failed", False),
                "date": make_aware(datetime.now())
            }
            # Create or update Screenshot by url
            screenshot_obj, created = Screenshot.objects.update_or_create(
                url=screenshot_json["url"],
                defaults=screenshot_defaults,
            )
            self.stdout.write(f"Screenshot saved for url: {screenshot_json['url']}")
                    