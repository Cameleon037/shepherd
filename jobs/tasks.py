from celery import shared_task
from jobs.utils import run_job
from django.contrib.auth import get_user_model
from suggestions.utils import auto_monitor_trusted_assets, auto_unmonitor_assets

"""
# Assets population
import_domaintools --projectid 1
import_crtsh --projectid 1
import_shodan --projectid 1
#import_fofa --projectid 1
scan_subfinder --projectid 1
get_domain_redirect --projectid 1

# Asset availability
get_dns_records --projectid 1

# Vulns Scanners
scan_nmap --projectid 1
scan_httpx --projectid 1
scan_nuclei --projectid 1 --nt

# Readjustment
scan_nuclei --update
scan_httpx --projectid 1 --missing-screenshots
"""

User = get_user_model()
scheduler_user = User.objects.get(username="scheduler")
project_id = 1

@shared_task
def test_task():
    print("Test task started")    
    command = 'test_job'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "Test completed"

@shared_task
def import_domaintools_task():
    command = 'import_domaintools'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "import_domaintools completed"

@shared_task
def import_crtsh_task():
    command = 'import_crtsh'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "import_crtsh completed"

@shared_task
def import_shodan_task():
    command = 'import_shodan'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "import_shodan completed"

@shared_task
def import_fofa_task():
    command = 'import_fofa'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "import_fofa completed"

@shared_task
def import_snow_cmdb_task():
    command = 'import_snow_cmdb'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "import_snow_cmdb completed"

@shared_task
def scan_porch_pirate_task():
    command = 'scan_porch-pirate'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_porch-pirate completed"

@shared_task
def scan_swaggerhub_task():
    command = 'scan_swaggerhub'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_swaggerhub completed"

@shared_task
def scan_ai_scribd_task():
    command = 'scan_ai_scribd'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_ai_scribd completed"

@shared_task
def scan_git_hound_task():
    command = 'scan_git-hound'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_git-hound completed"

@shared_task
def scan_ransomlook_task():
    command = 'scan_ransomlook'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_ransomlook completed"

@shared_task
def scan_subfinder_task():
    command = 'scan_subfinder'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_subfinder completed"

@shared_task
def get_domain_redirect_task():
    command = 'get_domain_redirect'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "get_domain_redirect completed"

@shared_task
def get_dns_records_task():
    command = 'get_dns_records'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "get_dns_records completed"

@shared_task
def scan_nmap_task():
    command = 'scan_nmap'
    args = f'--projectid {project_id} --scope external'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_nmap completed"

@shared_task
def scan_httpx_task():
    command = 'scan_httpx'
    args = f'--projectid {project_id} --scope external'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_httpx completed"

@shared_task
def scan_playwright_task():
    command = 'scan_playwright'
    args = f'--projectid {project_id} --scope external'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_playwright completed"

@shared_task
def scan_shepherdai_task():
    command = 'scan_shepherdai'
    args = f'--projectid {project_id}'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_shepherdai completed"

@shared_task
def scan_nuclei_task():
    command = 'scan_nuclei'
    args = f'--projectid {project_id} --nt --scope external'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_nuclei for new templates completed"

@shared_task
def scan_nuclei_new_assets_task():
    command = 'scan_nuclei'
    args = f'--projectid {project_id} --new-assets --scope external'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_nuclei for new templates completed"

@shared_task
def scan_nuclei_update_task():
    command = 'scan_nuclei'
    args = '--update'
    run_job(command, args, None, user=scheduler_user)
    return "scan_nuclei --update completed"

@shared_task
def scan_httpx_missing_screenshots_task():
    command = 'scan_httpx'
    args = f'--projectid {project_id} --missing-screenshots --scope external'
    run_job(command, args, project_id, user=scheduler_user)
    return "scan_httpx --missing-screenshots completed"

@shared_task
def auto_monitor_trusted_assets_task(project_id=None):
    """Automatically monitor trusted assets for a project"""
    if project_id is None:
        project_id = 1  # Default to project 1 if not specified
    
    count, assets = auto_monitor_trusted_assets(project_id)
    return f"auto_monitor_trusted_assets completed: {count} assets updated"

@shared_task
def auto_unmonitor_assets_task(project_id=None):
    """Automatically unmonitor inactive assets for a project"""
    if project_id is None:
        project_id = 1  # Default to project 1 if not specified
    
    count, assets = auto_unmonitor_assets(project_id)
    return f"auto_unmonitor_assets completed: {count} assets unmonitored"
