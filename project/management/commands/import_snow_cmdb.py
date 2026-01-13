import requests
import json
import base64
import uuid
import tldextract
import re
from datetime import datetime, timezone
import dateparser

from project.models import Project, Asset

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.utils.timezone import make_aware


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def get_snow_auth_header(self, username, password):
        """Create basic auth header for ServiceNow"""
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
        return f"Basic {encoded_credentials}"

    def get_snow_servers(self, snow_url, username, password):
        """Fetch servers from ServiceNow CMDB table"""
        url = f"{snow_url}/api/now/table/cmdb_ci_server"
        
        headers = {
            'Authorization': self.get_snow_auth_header(username, password),
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # Query for operational servers
        params = {
            'sysparm_query': 'operational_status=1^ORoperational_status=2',  # Active or Inactive but operational
            'sysparm_fields': 'name,host_name,fqdn,ip_address,operational_status,state,classification,os_name,os_version,location,serial_number,sys_id,u_application_owner',
            'sysparm_limit': 1000
        }
        
        all_servers = []
        offset = 0
        
        while True:
            params['sysparm_offset'] = offset
            try:
                response = requests.get(url, headers=headers, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                servers = data.get('result', [])

                
                if not servers:
                    break
                    
                all_servers.extend(servers)
                offset += len(servers)
                
                # If we got less than the limit, we've reached the end
                if len(servers) < 1000:
                    break
                    
            except requests.exceptions.RequestException as e:
                self.stdout.write(f"[-] Error fetching servers from ServiceNow: {e}")
                break
                
        return all_servers

    def normalize_hostname(self, hostname):
        """Convert hostname to FQDN format if needed"""
        if not hostname:
            return None
            
        # Clean the hostname
        hostname = hostname.strip().lower()
        
        # If it's already an FQDN (contains dots), return as is
        if '.' in hostname:
            return hostname
            
        # If it's just a hostname, add the internal domain from settings
        internal_domain = settings.SNOW_INTERNAL_DOMAIN
        return f"{hostname}.{internal_domain}"

    def extract_emails(self, raw_value):
        """Extract valid email addresses from a potentially messy string"""
        if not raw_value or not isinstance(raw_value, str):
            return ''
        
        # Simple email regex pattern
        email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        
        # Find all potential emails in the string
        found_emails = email_pattern.findall(raw_value.lower())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_emails = []
        for email in found_emails:
            if email not in seen:
                seen.add(email)
                unique_emails.append(email)
        
        return ', '.join(unique_emails)

    def handle(self, *args, **options):
        # Get ServiceNow credentials from settings
        snow_url = settings.SNOW_URL
        username = settings.SNOW_USERNAME
        password = settings.SNOW_PASSWORD
        
        if not all([snow_url, username, password]):
            raise CommandError("ServiceNow credentials are required. Set SNOW_URL, SNOW_USERNAME, and SNOW_PASSWORD in settings.")
        
        # Ensure URL doesn't end with slash
        snow_url = snow_url.rstrip('/')
        
        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        if not projects.exists():
            self.stdout.write("[-] No projects found matching the criteria")
            return

        total_asset_count = 0
        
        # Fetch servers from ServiceNow
        self.stdout.write("[+] Fetching servers from ServiceNow CMDB...")
        servers = self.get_snow_servers(snow_url, username, password)
        
        if not servers:
            self.stdout.write("[-] No servers found in ServiceNow CMDB")
            return
            
        self.stdout.write(f"[+] Found {len(servers)} servers in ServiceNow CMDB")
        
        for prj in projects:
            self.stdout.write(f"[+] Processing project: {prj.projectname}")
            asset_count = 0
            
            for server in servers:
                # Try to get hostname from various fields, prioritizing FQDN
                hostname = None
                fqdn = None
                
                # First try fqdn field
                if server.get('fqdn'):
                    fqdn = server['fqdn'].strip()
                # Then try name field
                elif server.get('name'):
                    fqdn = server['name'].strip()
                # Then try host_name field
                elif server.get('host_name'):
                    fqdn = server['host_name'].strip()

                fqdn = self.normalize_hostname(fqdn)
                
                if not fqdn:
                    continue
                
                # Skip if it's not a valid domain format
                parsed_obj = tldextract.extract(fqdn)
                if not parsed_obj.domain or not parsed_obj.suffix:
                    continue
                
                # Extract owner emails
                owner_emails = self.extract_emails(server.get('u_application_owner', ''))
                
                # Create asset details
                asset_data = {
                    "related_keyword": None,  # No keyword for internal assets
                    "related_project": prj,
                    "type": 'domain',
                    "subtype": 'subdomain',
                    "value": fqdn,
                    "source": 'servicenow_cmdb',
                    "scope": 'internal',
                    "link": f"{snow_url}/nav_to.do?uri=cmdb_ci_server.do?sys_id={server.get('sys_id', '')}",
                    "raw": server,
                    "monitor": True,
                    "owner": owner_emails,
                    "creation_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                    "last_seen_time": make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds"))),
                }
                
                # Build description from server details
                description_parts = []
                if server.get('os_name'):
                    os_info = server['os_name']
                    if server.get('os_version'):
                        os_info += f" {server['os_version']}"
                    description_parts.append(f"OS: {os_info}")
                
                if server.get('classification'):
                    description_parts.append(f"Classification: {server['classification']}")
                
                if server.get('state'):
                    description_parts.append(f"State: {server['state']}")
                
                # Handle location object properly
                if server.get('location'):
                    location = server['location']
                    if isinstance(location, dict) and location.get('value'):
                        description_parts.append(f"Location: {location['value']}")
                    elif isinstance(location, str):
                        description_parts.append(f"Location: {location}")
                
                if server.get('serial_number'):
                    description_parts.append(f"Serial: {server['serial_number']}")
                
                if server.get('ip_address'):
                    description_parts.append(f"IP: {server['ip_address']}")
                
                # Add original hostname if different from FQDN
                if hostname and hostname != fqdn:
                    description_parts.append(f"Hostname: {hostname}")
                
                asset_data["description"] = ", ".join(description_parts)
                
                # Set active status based on operational status
                operational_status = server.get('operational_status')
                if operational_status == '1':  # Active
                    asset_data["active"] = True
                elif operational_status == '2':  # Inactive
                    asset_data["active"] = False
                else:
                    asset_data["active"] = None
                
                # Create or update asset
                item_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{fqdn}:{prj.id}:servicenow")
                asset, created = Asset.objects.get_or_create(uuid=item_uuid, defaults=asset_data)
                
                if not created:
                    # Update existing asset
                    asset.raw = server
                    asset.last_seen_time = make_aware(dateparser.parse(datetime.now().isoformat(sep=" ", timespec="seconds")))
                    asset.description = asset_data["description"]
                    asset.active = asset_data["active"]
                    asset.link = asset_data["link"]
                    asset.monitor = asset_data["monitor"]
                    asset.owner = owner_emails
                    
                    # Update source if not already present
                    if 'servicenow_cmdb' not in asset.source:
                        asset.source = f"{asset.source}, servicenow_cmdb" if asset.source else "servicenow_cmdb"
                    
                    asset.save()
                
                asset_count += 1
            
            self.stdout.write(f"[+] Processed {asset_count} assets for project {prj.projectname}")
            total_asset_count += asset_count
        
        self.stdout.write(f"[+] Total assets processed: {total_asset_count}")
