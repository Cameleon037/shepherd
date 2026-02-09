import asyncio
import base64
import re
from urllib.parse import urlparse
from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware
from datetime import datetime
from project.models import Asset, Project
from findings.models import Screenshot
from django.conf import settings
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError, Error as PlaywrightError


class Command(BaseCommand):
    help = 'Run Playwright screenshot capture against http endpoints'

    def add_arguments(self, parser):
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
        parser.add_argument(
            '--max-concurrent',
            type=int,
            default=20,
            help='Maximum number of concurrent browser contexts (default: 20)',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Process URLs in batches to prevent resource exhaustion (default: 100)',
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=30000,
            help='Timeout per URL in milliseconds (default: 30000)',
        )
        parser.add_argument(
            '--viewport-width',
            type=int,
            default=1920,
            help='Screenshot viewport width (default: 1920)',
        )
        parser.add_argument(
            '--viewport-height',
            type=int,
            default=1080,
            help='Screenshot viewport height (default: 1080)',
        )
        parser.add_argument(
            '--headless',
            action='store_true',
            default=True,
            help='Run browser in headless mode (default: True)',
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

        playwright_urls = []
        for active_domain in active_domains:
            active_domain_urls = []
            ports = active_domain.port_set.all()
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
            playwright_urls += active_domain_urls

        self.stdout.write(f"Collected {len(playwright_urls)} URLs from {len(active_domains)} domains")
        
        if not playwright_urls:
            self.stdout.write("No URLs to process.")
            return

        # Run async screenshot capture
        max_concurrent = options.get('max_concurrent', 20)
        timeout = options.get('timeout', 30000)
        viewport_width = options.get('viewport_width', 1920)
        viewport_height = options.get('viewport_height', 1080)
        headless = options.get('headless', True)
        batch_size = options.get('batch_size', 100)

        self.stdout.write(f"Processing {len(playwright_urls)} URLs in batches of {batch_size}")

        # Process URLs in batches to prevent resource exhaustion
        total_batches = (len(playwright_urls) + batch_size - 1) // batch_size
        total_processed = 0
        total_success = 0
        total_failed = 0
        
        for batch_num in range(total_batches):
            start_idx = batch_num * batch_size
            end_idx = min(start_idx + batch_size, len(playwright_urls))
            batch_urls = playwright_urls[start_idx:end_idx]
            
            # Run the async function for this batch
            batch_results = asyncio.run(self.capture_screenshots(
                batch_urls,
                max_concurrent=max_concurrent,
                timeout=timeout,
                viewport_width=viewport_width,
                viewport_height=viewport_height,
                headless=headless
            ))
            
            # Save results to DB immediately to free memory
            batch_success, batch_failed = self._save_results_to_db(batch_results)
            total_success += batch_success
            total_failed += batch_failed
            total_processed += len(batch_results)
            percentage = (total_processed / len(playwright_urls)) * 100
            
            self.stdout.write(f"Batch {batch_num + 1}/{total_batches}: {batch_success} success, {batch_failed} failed ({percentage:.1f}% complete)")
            
            # Small delay between batches to let resources recover
            if batch_num < total_batches - 1:
                import time
                time.sleep(2)
        
        self.stdout.write(f"\nFinal summary: {total_success} successful, {total_failed} failed")

    def _save_results_to_db(self, results):
        """Save results to database and return success/fail counts"""
        success_count = 0
        failed_count = 0
        for result in results:
            try:
                # Extract domain from url and match to Asset
                parsed_url = urlparse(result["url"])
                domain_value = parsed_url.hostname
                domain_obj = None
                if domain_value:
                    domain_obj = Asset.objects.filter(value__iexact=domain_value).first()
                    
                screenshot_defaults = {
                    "domain": domain_obj,
                    "technologies": result.get("technologies", ""),
                    "screenshot_base64": result.get("screenshot_base64", ""),
                    "title": result.get("title", ""),
                    "webserver": result.get("webserver", ""),
                    "host_ip": result.get("host_ip", ""),
                    "status_code": result.get("status_code", "0"),  # Default to "0" if somehow None
                    "response_body": result.get("response_body", ""),
                    "failed": result.get("failed", False),
                    "date": make_aware(datetime.now())
                }

                # If status code is 0, do not store the screenshot
                if screenshot_defaults["status_code"] == "0":
                    failed_count += 1
                    continue

                # Create or update Screenshot by url
                screenshot_obj, created = Screenshot.objects.update_or_create(
                    url=result["url"],
                    defaults=screenshot_defaults,
                )
                
                if result.get("failed"):
                    failed_count += 1
                else:
                    success_count += 1
                    self.stdout.write(f"[SUCCESS] Screenshot saved for url: {result['url']}")
            except Exception as e:
                failed_count += 1
        
        return success_count, failed_count

    async def capture_screenshots(self, urls, max_concurrent=20, timeout=30000, 
                                  viewport_width=1920, viewport_height=1080, headless=True):
        """Capture screenshots for a list of URLs using Playwright"""
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=headless,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--disable-gpu',
                ]
            )

            async def capture_single_url(url):
                """Capture screenshot for a single URL"""
                async with semaphore:
                    result = {
                        "url": url,
                        "screenshot_base64": "",
                        "title": "",
                        "webserver": "",
                        "host_ip": "",
                        "status_code": "0",  # Default to "0" for unknown/error cases
                        "response_body": "",
                        "technologies": "",
                        "failed": False,
                    }

                    context = None
                    page = None
                    try:
                        # Create a new context for each URL
                        context = await browser.new_context(
                            viewport={'width': viewport_width, 'height': viewport_height},
                            ignore_https_errors=True,
                            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                        )

                        page = await context.new_page()

                        # Set timeout
                        page.set_default_timeout(timeout)

                        # Navigate to URL
                        try:
                            response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout)
                            
                            # Get status code - always set a value
                            if response:
                                result["status_code"] = str(response.status)
                                
                                # Get webserver from headers
                                server_header = response.headers.get('server', '')
                                if server_header:
                                    result["webserver"] = server_header
                            else:
                                # Response is None, set default status code
                                result["status_code"] = "0"
                            
                            # Wait a bit for page to render
                            await asyncio.sleep(1)
                            
                            # Get page title
                            try:
                                title = await page.title()
                                result["title"] = title or ""
                            except:
                                pass

                            # Get page content (first 100000 chars to avoid huge responses)
                            try:
                                content = await page.content()
                                result["response_body"] = content[:100000] if content else ""
                                
                                # Try to detect technologies from HTML
                                technologies = self.detect_technologies(content)
                                if technologies:
                                    result["technologies"] = ",".join(technologies)
                            except:
                                pass

                            # Extract host IP from URL
                            parsed = urlparse(url)
                            result["host_ip"] = parsed.hostname or ""

                            # Take screenshot
                            screenshot_bytes = await page.screenshot(
                                full_page=False,
                                type='png',
                                timeout=10000
                            )
                            result["screenshot_base64"] = base64.b64encode(screenshot_bytes).decode('utf-8')

                        except PlaywrightTimeoutError:
                            result["failed"] = True
                            result["status_code"] = "0"
                            result["response_body"] = "Timeout waiting for page to load"
                        except PlaywrightError as e:
                            result["failed"] = True
                            result["status_code"] = "0"
                            result["response_body"] = f"Playwright error: {str(e)}"
                        except Exception as e:
                            result["failed"] = True
                            result["status_code"] = "0"
                            result["response_body"] = f"Error: {str(e)}"
                        finally:
                            # Always close page and context
                            try:
                                if page:
                                    await asyncio.wait_for(page.close(), timeout=2)
                            except:
                                pass
                            try:
                                if context:
                                    await asyncio.wait_for(context.close(), timeout=2)
                            except:
                                pass

                    except Exception as e:
                        result["failed"] = True
                        result["status_code"] = "0"
                        result["response_body"] = f"Unexpected error: {str(e)}"
                    finally:
                        # Final cleanup attempt
                        try:
                            if context:
                                await asyncio.wait_for(context.close(), timeout=1)
                        except:
                            pass

                    return result

            # Wrap each task in a timeout to prevent indefinite hangs
            task_timeout = (timeout / 1000.0) + 10
            
            async def capture_with_timeout(url):
                """Wrap capture_single_url with a timeout to prevent hangs"""
                try:
                    return await asyncio.wait_for(
                        capture_single_url(url),
                        timeout=task_timeout
                    )
                except asyncio.TimeoutError:
                    return {
                        "url": url,
                        "screenshot_base64": "",
                        "title": "",
                        "webserver": "",
                        "host_ip": "",
                        "status_code": "0",
                        "response_body": f"Task timeout exceeded ({task_timeout}s)",
                        "technologies": "",
                        "failed": True,
                    }
                except Exception as e:
                    return {
                        "url": url,
                        "screenshot_base64": "",
                        "title": "",
                        "webserver": "",
                        "host_ip": "",
                        "status_code": "0",
                        "response_body": f"Task wrapper error: {str(e)}",
                        "technologies": "",
                        "failed": True,
                    }
            
            tasks = [capture_with_timeout(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and convert to list
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        "url": urls[i],
                        "screenshot_base64": "",
                        "title": "",
                        "webserver": "",
                        "host_ip": "",
                        "status_code": "0",
                        "response_body": f"Exception: {str(result)}",
                        "technologies": "",
                        "failed": True,
                    })
                else:
                    processed_results.append(result)

            await browser.close()

        return processed_results

    def detect_technologies(self, html_content):
        """Detect technologies from HTML content"""
        if not html_content:
            return []
        
        technologies = []
        html_lower = html_content.lower()
        
        # Common technology patterns
        tech_patterns = {
            'WordPress': [r'wp-content', r'wordpress', r'/wp-includes/'],
            'Drupal': [r'drupal', r'/sites/all/'],
            'Joomla': [r'joomla', r'/media/system/'],
            'React': [r'react', r'__REACT_DEVTOOLS'],
            'Vue.js': [r'vue\.js', r'__VUE__'],
            'Angular': [r'angular', r'ng-'],
            'jQuery': [r'jquery', r'\.jquery'],
            'Bootstrap': [r'bootstrap', r'bs-'],
            'ASP.NET': [r'asp\.net', r'__VIEWSTATE'],
            'PHP': [r'\.php', r'php/'],
            'Laravel': [r'laravel_session', r'laravel'],
            'Django': [r'csrftoken', r'django'],
            'Flask': [r'flask', r'werkzeug'],
            'Express': [r'express', r'x-powered-by.*express'],
            'Nginx': [r'nginx'],
            'Apache': [r'apache', r'apache/'],
            'IIS': [r'iis', r'microsoft-iis'],
            'Cloudflare': [r'cloudflare', r'cf-ray'],
            'AWS': [r'aws', r'amazonaws'],
            'Google Analytics': [r'google-analytics', r'ga\.js', r'gtag'],
            'Google Tag Manager': [r'googletagmanager', r'gtm\.js'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    if tech not in technologies:
                        technologies.append(tech)
                    break
        
        return technologies

