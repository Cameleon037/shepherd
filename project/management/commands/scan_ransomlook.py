import html
import requests
from project.models import Project, Keyword
from findings.models import Finding
import json

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

from django.utils.timezone import make_aware
from datetime import datetime, timedelta


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )
        parser.add_argument(
            '--days',
            type=int,
            default=14,
            help='Number of days to look back for posts (default: 14)',
        )

    def handle(self, *args, **options):
        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']
        
        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            
            # Step 1: Build a list of all ransomlook_supplier keywords
            keywords = prj.keyword_set.filter(enabled=True, ktype='ransomlook_supplier')
            
            if not keywords.exists():
                self.stdout.write(f'[+] No enabled "ransomlook_supplier" keywords found for project {prj.projectname}')
                continue
            
            # Collect all keyword objects (not strings)
            all_suppliers = list(keywords)
            
            if not all_suppliers:
                self.stdout.write(f'[+] No suppliers found in ransomlook_supplier keywords')
                continue
            
            self.stdout.write(f"[+] Monitoring {len(all_suppliers)} keyword(s)")
            
            # Step 2: Query the recent RansomLook posts
            try:
                base_url = getattr(settings, 'RANSOMLOOK_API_URL', 'https://www.ransomlook.io/api/recent')
                headers = {
                    "Accept": "application/json"
                }
                
                # Calculate date threshold
                since_date = (datetime.now() - timedelta(days=options.get('days', 14))).isoformat()
                params = {
                    "since": since_date,
                    "limit": 100
                }
                
                self.stdout.write(f'[+] Querying RansomLook API for posts since {since_date}')
                response = requests.get(base_url, headers=headers, params=params, timeout=30)
                response.raise_for_status()
                result = response.json()
                
                # Handle API response structure
                posts = []
                if isinstance(result, list):
                    posts = result
                elif isinstance(result, dict):
                    posts = result.get("posts", [])
                
                if not posts:
                    self.stdout.write(f'[+] No recent posts found in last {options.get("days", 14)} days')
                    continue
                
                self.stdout.write(f'[+] Found {len(posts)} recent posts to check')
                
                # Step 3: Loop through all posts and check if any supplier keyword appears
                findings_count = 0
                for post in posts:
                    # Extract post information
                    post_title = post.get('post_title', '')
                    description = post.get('description', '')
                    link = post.get('link', '')
                    discovered = post.get('discovered', '')
                    group_name = post.get('group_name', '')
                    
                    # Use link value directly (can be empty string)
                    link = link if link else ''
                    
                    # Combine all text fields for matching
                    search_text = f"{post_title}".lower()
                    
                    # Check if any supplier name appears in the post
                    matched_supplier = None
                    for kw_obj in all_suppliers:
                        # Unescape the keyword during matching
                        supplier = html.unescape(kw_obj.keyword)
                        # Check if any supplier from this keyword matches
                        if supplier.lower() in search_text.split(" "):
                            matched_supplier = kw_obj
                            break
                    
                    # If a supplier appears, add a finding and go to next post
                    if matched_supplier:
                        finding_name = f"Supplier breach: {matched_supplier} mentioned in ransomware leak"
                        
                        # Build description with matching supplier at the beginning
                        description_parts = []
                        description_parts.append(f"Matching Supplier: {matched_supplier}")
                        if group_name:
                            description_parts.append(f"Ransomware Group: {group_name}")
                        if post_title:
                            description_parts.append(f"Victim: {post_title}")
                        if discovered:
                            description_parts.append(f"Discovered: {discovered}")
                        if description:
                            # Truncate description if too long
                            desc_text = description[:1000] + "..." if len(description) > 1000 else description
                            description_parts.append(f"Description: {desc_text}")
                        
                        finding_description = " | ".join(description_parts) if description_parts else f"Matching Supplier: {matched_supplier}"
                        
                        # Use get_or_create based on description to avoid duplicates
                        finding_obj, created = Finding.objects.get_or_create(
                            description=finding_description,
                            defaults={
                                'keyword': matched_supplier,
                                'source': 'ransomlook',
                                'name': finding_name,
                                'type': 'supplier_breach',
                                'url': '',
                                'severity': 'high',  # Supplier breaches are high severity
                                'scan_date': make_aware(datetime.now()),
                                'last_seen': make_aware(datetime.now()),
                            }
                        )
                        
                        # Update dates and keyword if finding already existed
                        if not created:
                            finding_obj.scan_date = make_aware(datetime.now())
                            finding_obj.last_seen = finding_obj.scan_date
                            finding_obj.keyword = matched_supplier
                            finding_obj.save()
                        
                        findings_count += 1
                        if created:
                            self.stdout.write(f'    [+] New finding: {finding_name}')
                        else:
                            self.stdout.write(f'    [+] Updated finding: {finding_name}')
                    
                    # If no match, continue to next post (implicitly handled by loop)
                
                self.stdout.write(f'[+] Total findings created/updated: {findings_count}')
                        
            except requests.exceptions.RequestException as e:
                self.stderr.write(f'[+] Error querying RansomLook API: {e}')
            except json.JSONDecodeError as e:
                self.stderr.write(f'[+] Error parsing RansomLook API response: {e}')
            except Exception as error:
                self.stderr.write(f'[+] Error running RansomLook scan: {error}')
