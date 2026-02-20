import html
import tempfile
import subprocess
from project.models import Project, Keyword, Asset
from project.scan_utils import add_common_scan_arguments
from findings.models import Finding
import re
import json

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.conf import settings

from django.utils.timezone import make_aware
from datetime import datetime

class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='Filter by specific project ID')
        add_common_scan_arguments(parser)
        parser.add_argument(
            '--dig-files',
            action='store_true',
            help='Dig through repo files to find more secrets (CPU intensive)',
        )
        parser.add_argument(
            '--dig-commits',
            action='store_true',
            help='Dig through commit history to find more secrets (CPU intensive)',
        )

    def handle(self, *args, **options):

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            
            # Get keywords for this project
            keywords = prj.keyword_set.filter(enabled=True)
            
            # Filter by keyword type - only scan git-hound_keyword types
            keywords = keywords.filter(ktype='git-hound_keyword')
            
            for kw in keywords:
                keyword = html.unescape(kw.keyword)
                
                self.stdout.write(f"[+] GitHound search: {keyword}")
                self.githound_scan(kw, prj, options)

    def githound_scan(self, kw, prj, options):
        """Run git-hound scan for a keyword and create findings"""
        
        keyword = html.unescape(kw.keyword)
        
        # Build the git-hound command
        command = ['./git-hound', '--query', keyword, '--many-results', '--json']
        
        # Add dig flags (enabled by default)
        command.append('--dig-files')
        command.append('--dig-commits')
        
        # Add other useful flags
        # command.extend(['--no-scoring'])  # Include all results, let user filter
        
        # Get working directory from settings if configured
        working_dir = getattr(settings, 'GITHOUND_WORKING_DIR', None)
        
        try:
            # Run git-hound and capture output
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                # timeout=300,  # 5 minute timeout
                cwd=working_dir  # Set working directory if configured
            )
            
            if result.returncode != 0:
                self.stderr.write(f'[+] Error scanning keyword {keyword}: {result.stderr}')
                return
            
            output = result.stdout.strip()
            # self.stdout.write(output)

            if not output:
                self.stdout.write(f'    [+] No results found for {keyword}')
                return
            
            # Parse JSON output
            # GitHound outputs one JSON object per line
            findings_count = 0
            for line in output.split('\n'):
                if not line.strip():
                    continue
                    
                try:
                    json_result = json.loads(line)
                    
                    # Extract relevant information from git-hound output
                    # GitHound JSON structure may vary, adjust based on actual output
                    repo_url = json_result.get('repo', {}).get('url', '') if isinstance(json_result.get('repo'), dict) else json_result.get('repo', '')
                    file_path = json_result.get('file', '')
                    match_string = json_result.get('match', '')
                    line_number = json_result.get('line', '')
                    secret_type = json_result.get('type', 'API Key')
                    
                    # Build description
                    description_parts = []
                    if file_path:
                        description_parts.append(f"File: {file_path}")
                    if line_number:
                        description_parts.append(f"Line: {line_number}")
                    if match_string:
                        # Truncate match string if too long
                        truncated_match = match_string[:100] + "..." if len(match_string) > 100 else match_string
                        description_parts.append(f"Match: {truncated_match}")
                    
                    description = " | ".join(description_parts) if description_parts else "Potential secret leak found"
                    
                    # Build finding name
                    finding_name = f"{secret_type} leak in {repo_url}" if repo_url else f"{secret_type} leak"
                    
                    # Build URL (GitHub file URL)
                    file_url = json_result.get('url', repo_url)
                    
                    # Determine severity based on secret type
                    severity = 'high' if ('api' in secret_type.lower() or 'key' in secret_type.lower()) else 'medium'
                    
                    # Store the result as a Finding object
                    defaults = {
                        'keyword': kw,
                        'source': 'git-hound',
                        'name': finding_name,
                        'type': 'data_leak',
                        'severity': severity,
                        'scan_date': make_aware(datetime.now()),
                        'last_seen': make_aware(datetime.now()),
                    }
                    
                    finding_obj, created = Finding.objects.get_or_create(
                        url=file_url,
                        description=description,
                        defaults=defaults
                    )
                    
                    # Update dates for existing findings
                    if not created:
                        finding_obj.scan_date = make_aware(datetime.now())
                        finding_obj.last_seen = finding_obj.scan_date
                        finding_obj.save()
                    findings_count += 1
                    
                    if created:
                        self.stdout.write(f'    [+] New finding: {finding_name}')
                    else:
                        self.stdout.write(f'    [+] Updated finding: {finding_name}')
                        
                except json.JSONDecodeError as e:
                    self.stderr.write(f'    [+] Error parsing JSON line: {e}')
                    continue
                except Exception as e:
                    self.stderr.write(f'    [+] Error processing result: {e}')
                    continue
            
            self.stdout.write(f'[+] Total findings created/updated: {findings_count}')
                    
        except subprocess.TimeoutExpired:
            self.stderr.write(f'[+] GitHound scan timed out for keyword {keyword}')
        except Exception as error:
            self.stderr.write(f'[+] Error running git-hound scan: {error}')

