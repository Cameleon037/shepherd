import json
import os
import tempfile
import threading

from django.db.models import Q

from assets.models import Asset
from jobs.utils import run_job
from scanners.scan_utils import write_uuids_file


def filter_assets_for_project(project_id, filters):
    queryset = Asset.objects.filter(related_project_id=project_id, monitor=True)

    asset_type = (filters.get('type') or '').strip()
    if asset_type:
        queryset = queryset.filter(type=asset_type)

    scope = (filters.get('scope') or '').strip()
    if scope:
        queryset = queryset.filter(scope__iexact=scope)

    sources = filters.get('sources') or []
    if isinstance(sources, str):
        sources = [sources]
    sources = [src.strip() for src in sources if src and src.strip()]
    if sources:
        query = Q()
        for src in sources:
            query |= Q(source__icontains=src)
        queryset = queryset.filter(query)

    name = (filters.get('name') or '').strip()
    if name:
        queryset = queryset.filter(value__icontains=name)

    return queryset


def run_scan_jobs(project_id, user, selected_uuids, scan_new_assets, scans):
    selected_uuids = [str(uuid) for uuid in (selected_uuids or [])]
    threads = []
    triggered_messages = []

    def add_message(text):
        if text:
            triggered_messages.append(text)

    def launch(command, extra=""):
        args = f'--projectid {project_id}{extra}'
        if selected_uuids:
            uuids_file = write_uuids_file(selected_uuids)
            args += f' --uuids-file {uuids_file}'
        if scan_new_assets:
            args += ' --new-assets'
        run_job(command, args, project_id, user)

    def scan_nmap():
        launch('scan_nmap')

    def scan_httpx():
        launch('scan_httpx')

    def scan_playwright():
        launch('scan_playwright')

    def scan_katana():
        launch('scan_katana')

    def scan_shepherdai():
        launch('scan_shepherdai')

    def scan_nuclei():
        launch('scan_nuclei')

    def scan_nuclei_nt():
        launch('scan_nuclei', ' --nt')

    def scan_dns_records():
        launch('get_dns_records')

    def scan_domain_redirect():
        launch('get_domain_redirect')

    def scan_domaintools():
        launch('scan_domaintools')

    scan_dns_records_flag = scans.get('scan_dns_records')
    scan_domain_redirect_flag = scans.get('scan_domain_redirect')
    scan_domaintools_flag = scans.get('scan_domaintools')
    scan_nmap_flag = scans.get('scan_nmap')
    scan_httpx_flag = scans.get('scan_httpx')
    scan_playwright_flag = scans.get('scan_playwright')
    scan_katana_flag = scans.get('scan_katana')
    scan_shepherdai_flag = scans.get('scan_shepherdai')
    scan_nuclei_flag = scans.get('scan_nuclei')
    scan_nuclei_new_flag = scans.get('scan_nuclei_new_templates')

    # Check if we need to chain Nmap -> Screenshot (HTTPX or Playwright) and/or Katana
    screenshot_selected = scan_httpx_flag or scan_playwright_flag
    nmap_then_screenshot = scan_nmap_flag and screenshot_selected
    nmap_then_katana = scan_nmap_flag and scan_katana_flag
    nmap_chained = nmap_then_screenshot or nmap_then_katana

    # Primary threads: all scans except Shepherd AI (which runs last)
    primary_threads = []

    if scan_dns_records_flag:
        primary_threads.append(threading.Thread(target=scan_dns_records))
        add_message('DNS Records scan has been triggered in the background. (check jobs)')

    if scan_domain_redirect_flag:
        primary_threads.append(threading.Thread(target=scan_domain_redirect))
        add_message('Domain Redirect scan has been triggered in the background. (check jobs)')

    if scan_domaintools_flag:
        primary_threads.append(threading.Thread(target=scan_domaintools))
        add_message('DomainTools registrant scan has been triggered in the background. (check jobs)')

    if nmap_chained:
        # Create a chained thread: Nmap runs first, then screenshot engine(s) and/or Katana after completion
        def nmap_then_dependent_scans():
            scan_nmap()  # This blocks until Nmap job completes
            if scan_httpx_flag:
                scan_httpx()
            if scan_playwright_flag:
                scan_playwright()
            if scan_katana_flag:
                scan_katana()

        primary_threads.append(threading.Thread(target=nmap_then_dependent_scans))
        add_message('Nmap scan has been triggered in the background. (check jobs)')
        if scan_httpx_flag:
            add_message('Httpx scan will start after Nmap completes. (check jobs)')
        if scan_playwright_flag:
            add_message('Playwright scan will start after Nmap completes. (check jobs)')
        if scan_katana_flag:
            add_message('Katana scan will start after Nmap completes. (check jobs)')
    else:
        # No dependency - run independently
        if scan_nmap_flag:
            primary_threads.append(threading.Thread(target=scan_nmap))
            add_message('Nmap scan has been triggered in the background. (check jobs)')

        if scan_httpx_flag:
            primary_threads.append(threading.Thread(target=scan_httpx))
            add_message('Httpx scan has been triggered in the background. (check jobs)')

        if scan_playwright_flag:
            primary_threads.append(threading.Thread(target=scan_playwright))
            add_message('Playwright scan has been triggered in the background. (check jobs)')

        if scan_katana_flag:
            primary_threads.append(threading.Thread(target=scan_katana))
            add_message('Katana scan has been triggered in the background. (check jobs)')

    if scan_nuclei_flag:
        primary_threads.append(threading.Thread(target=scan_nuclei))
        add_message('Nuclei scan has been triggered in the background. (check jobs)')

    if scan_nuclei_new_flag:
        primary_threads.append(threading.Thread(target=scan_nuclei_nt))
        add_message('Nuclei scan for new templates has been triggered in the background. (check jobs)')

    # Handle Shepherd AI: it should run after all other scans complete
    if scan_shepherdai_flag:
        if primary_threads:
            # Shepherd AI runs after all primary scans complete
            def run_shepherdai_after_all():
                # Start all primary threads
                for t in primary_threads:
                    t.start()
                # Wait for all primary threads to complete
                for t in primary_threads:
                    t.join()
                # Now run Shepherd AI
                scan_shepherdai()

            threads.append(threading.Thread(target=run_shepherdai_after_all))
            add_message('Shepherd AI will run after all other scans complete. (check jobs)')
        else:
            # No other scans selected, just run Shepherd AI directly
            threads.append(threading.Thread(target=scan_shepherdai))
            add_message('Shepherd AI scan has been triggered in the background. (check jobs)')
    else:
        # No Shepherd AI - just add all primary threads to be started
        threads.extend(primary_threads)

    for thread in threads:
        thread.start()

    return triggered_messages


def run_burp_scan(project_id, user, urls):
    """Trigger a Burp Suite scan against the given URLs in a background thread."""
    # Write URLs to a temp file to avoid OS argument length limits
    fd, urls_file = tempfile.mkstemp(prefix='burp_urls_', suffix='.json', dir='/tmp')
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(urls, f)
    except Exception:
        os.close(fd)
        raise

    args = f'--wait --urls-file {urls_file}'

    # Launch the job in a background thread so the request returns immediately
    thread = threading.Thread(
        target=run_job,
        args=('scan_burp', args, project_id, user),
    )
    thread.start()
