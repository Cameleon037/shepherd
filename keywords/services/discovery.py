import threading

from assets.utils import auto_monitor_trusted_assets
from jobs.utils import run_job


def run_discovery_jobs(project_id, user, keyword_ids, scans, auto_monitor, post_actions):
    """Launch keyword discovery scans, optionally chaining Subfinder and post-discovery actions.

    Returns (triggered_messages, launched) where launched is False when nothing was selected.
    """
    # Build keyword filter args
    keyword_args = ''
    if keyword_ids:
        keyword_args = f' --keyword-ids {",".join(str(k) for k in keyword_ids)}'

    threads = []
    triggered_messages = []

    def launch(command, extra=''):
        args = f'--projectid {project_id}{extra}'
        run_job(command, args, project_id, user)

    if scans.get('scan_crtsh'):
        threads.append(threading.Thread(target=lambda: launch('import_crtsh', keyword_args)))
        triggered_messages.append('Crt.sh scan triggered.')

    if scans.get('scan_domaintools'):
        threads.append(threading.Thread(target=lambda: launch('import_domaintools', keyword_args)))
        triggered_messages.append('DomainTools scan triggered.')

    if scans.get('scan_shodan'):
        threads.append(threading.Thread(target=lambda: launch('import_shodan', keyword_args)))
        triggered_messages.append('Shodan scan triggered.')

    if scans.get('scan_servicenow'):
        threads.append(threading.Thread(target=lambda: launch('import_snow_cmdb')))
        triggered_messages.append('ServiceNow CMDB import triggered.')

    if scans.get('scan_wiz'):
        threads.append(threading.Thread(target=lambda: launch('import_wiz')))
        triggered_messages.append('Wiz import triggered.')

    if scans.get('scan_fofa'):
        threads.append(threading.Thread(target=lambda: launch('import_fofa', keyword_args)))
        triggered_messages.append('FOFA scan triggered.')

    if scans.get('scan_porch_pirate'):
        threads.append(threading.Thread(target=lambda: launch('scan_porch-pirate', keyword_args)))
        triggered_messages.append('Porch-pirate scan triggered.')

    if scans.get('scan_swaggerhub'):
        threads.append(threading.Thread(target=lambda: launch('scan_swaggerhub', keyword_args)))
        triggered_messages.append('SwaggerHub scan triggered.')

    if scans.get('scan_ai_scribd'):
        threads.append(threading.Thread(target=lambda: launch('scan_ai_scribd', keyword_args)))
        triggered_messages.append('ShepherdAI + Scribd scan triggered.')

    if scans.get('scan_git_hound'):
        threads.append(threading.Thread(target=lambda: launch('scan_git-hound', keyword_args)))
        triggered_messages.append('GitHound scan triggered.')

    if scans.get('scan_ghleaks'):
        threads.append(threading.Thread(target=lambda: launch('scan_ghleaks', keyword_args)))
        triggered_messages.append('ghleaks scan triggered.')

    if scans.get('scan_ransomlook'):
        threads.append(threading.Thread(target=lambda: launch('scan_ransomlook', keyword_args)))
        triggered_messages.append('RansomLook scan triggered.')

    # Subfinder runs after discovery scans (step 3)
    run_subfinder = scans.get('scan_subfinder', False)

    # Check if any post-discovery actions are selected (step 4)
    run_dns_records = post_actions.get('dns_records', False)
    run_domain_redirect = post_actions.get('domain_redirect', False)
    has_post_actions = run_dns_records or run_domain_redirect or auto_monitor

    # Validate that at least something is selected
    if not threads and not run_subfinder and not has_post_actions:
        return triggered_messages, False

    # Start all discovery scan threads in parallel
    for thread in threads:
        thread.start()

    # If subfinder or post-actions are selected, run them in sequence after discovery
    if run_subfinder or has_post_actions:
        def run_sequential_actions():
            # Wait for all discovery scan threads to complete
            for t in threads:
                t.join()

            # Step 3: Run Subfinder (against starred domains)
            if run_subfinder:
                launch('scan_subfinder')

            # Step 4: Run post-discovery actions
            # Run Domain Redirect scan first
            if run_domain_redirect:
                launch('get_domain_redirect')

            # Run DNS Records scan
            if run_dns_records:
                launch('get_dns_records')

            # Auto-monitor trusted assets
            if auto_monitor:
                auto_monitor_trusted_assets(project_id)

        post_thread = threading.Thread(target=run_sequential_actions)
        post_thread.start()

        if run_subfinder:
            triggered_messages.append('Subfinder will run after discovery (on starred domains).')
        if run_domain_redirect:
            triggered_messages.append('Domain Redirect scan will run after Subfinder (if selected).')
        if run_dns_records:
            triggered_messages.append('DNS Records scan will run after Domain Redirect (if selected).')
        if auto_monitor:
            triggered_messages.append('Auto-monitor will be applied after all scans complete.')

    return triggered_messages, True
