from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap
import csv
from io import StringIO
from datetime import datetime
import socket
import dns.resolver
from collections import defaultdict

from project.models import Project
from findings.models import Port

from django.core.management.base import BaseCommand, CommandError
from django.utils.timezone import make_aware


"""
['host', 'hostname', 'hostname_type', 'protocol', 'port', 'name', 'state', 'product', 'extrainfo', 'reason', 'version', 'conf', 'cpe']
['3.111.7.95', 'www.tryloctite.in', 'user', 'tcp', '22', 'ssh', 'open', 'OpenSSH', 'Ubuntu Linux; protocol 2.0', 'syn-ack', '8.9p1 Ubuntu 3ubuntu0.7', '10', 'cpe:/o:linux:linux_kernel']
['3.111.7.95', 'ec2-3-111-7-95.ap-south-1.compute.amazonaws.com', 'PTR', 'tcp', '22', 'ssh', 'open', 'OpenSSH', 'Ubuntu Linux; protocol 2.0', 'syn-ack', '8.9p1 Ubuntu 3ubuntu0.7', '10', 'cpe:/o:linux:linux_kernel']
['3.111.7.95', 'www.tryloctite.in', 'user', 'tcp', '80', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
['3.111.7.95', 'ec2-3-111-7-95.ap-south-1.compute.amazonaws.com', 'PTR', 'tcp', '80', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
['3.111.7.95', 'www.tryloctite.in', 'user', 'tcp', '443', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
['3.111.7.95', 'ec2-3-111-7-95.ap-south-1.compute.amazonaws.com', 'PTR', 'tcp', '443', 'http', 'open', 'nginx', '', 'syn-ack', '', '10', 'cpe:/a:igor_sysoev:nginx']
"""

class Command(BaseCommand):
    help = 'Run Nmap scan for active domains in a specific project'

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

    def resolve_domain_to_ip(self, domain):
        """Resolve domain name to IP address using DNS A record"""
        try:
            # Try A record first (IPv4)
            answers = dns.resolver.resolve(domain, 'A')
            return str(answers[0])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            try:
                # Fallback to socket.gethostbyname
                return socket.gethostbyname(domain)
            except socket.gaierror:
                self.stderr.write(f"Could not resolve domain {domain}")
                return None
        except Exception as e:
            self.stderr.write(f"Error resolving domain {domain}: {e}")
            return None

    def handle(self, *args, **options):
        projectid = options.get('projectid')
        uuids_arg = options.get('uuids')
        scope_filter = options.get('scope')
        new_assets_only = options.get('new_assets')

        # Get the projects to scan
        if projectid:
            try:
                projects = [Project.objects.get(id=projectid)]
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            projects = Project.objects.all()

        for prj in projects:
            domains_qs = prj.asset_set.filter(monitor=True)
            # Filter by scope if provided
            if scope_filter:
                domains_qs = domains_qs.filter(scope=scope_filter)
            # Filter by uuids if provided
            if uuids_arg:
                uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
                domains_qs = domains_qs.filter(uuid__in=uuid_list)
            # Filter by new_assets_only if set
            if new_assets_only:
                domains_qs = domains_qs.filter(last_scan_time__isnull=True)

            if not domains_qs.exists():
                self.stdout.write(f"No domains found to scan for project {prj.projectname}")
                continue

            # Group domains by their resolved IP addresses
            ip_to_domains = defaultdict(list)
            unresolved_domains = []
            
            self.stdout.write(f"Resolving {domains_qs.count()} domains to IP addresses...")
            
            for domain in domains_qs:
                ip = self.resolve_domain_to_ip(domain.value)
                if ip:
                    ip_to_domains[ip].append(domain)
                    self.stdout.write(f"Resolved {domain.value} -> {ip}")
                else:
                    unresolved_domains.append(domain)
                    self.stdout.write(f"Could not resolve {domain.value}")

            # Scan each unique IP address only once
            self.stdout.write(f"Scanning {len(ip_to_domains)} unique IP addresses...")
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for ip, domains_for_ip in ip_to_domains.items():
                    future = executor.submit(self.nmap_scan_ip, ip, domains_for_ip)
                    futures.append(future)
                
                for future in as_completed(futures):
                    future.result()  # This will raise any exceptions caught during the scan

            # Handle unresolved domains separately (scan them directly)
            if unresolved_domains:
                self.stdout.write(f"Scanning {len(unresolved_domains)} unresolved domains directly...")
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self.nmap_scan_domain, domain.value, domain) for domain in unresolved_domains]
                    for future in as_completed(futures):
                        future.result()  # This will raise any exceptions caught during the scan

    def nmap_scan_ip(self, ip_address, domains_for_ip):
        """Scan a single IP address and distribute results to all domains that point to it"""
        self.stdout.write(f"Nmap scan starting for IP {ip_address} (affects {len(domains_for_ip)} domains)")
        try:
            port_list = []
            nm = nmap.PortScanner()
            nm.scan(
                ip_address,
                arguments='-F -Pn -sC -sV -T4 --version-light',
            )

            f = StringIO(nm.csv())
            r = csv.reader(f, delimiter=';')
            firstRow = None
            for row in r:
                # Skip the first row
                if row[0] == 'host':
                    firstRow = row
                    continue
                new_row = dict(zip(firstRow, row))
                pdict = {
                    'port': int(new_row['port']),
                    'banner': new_row['name'] + '::' + new_row['extrainfo'] + '::' + new_row['version'],
                    'status': new_row['state'],
                    'product': new_row['product'],
                    'cpe': new_row['cpe']
                }
                if pdict not in port_list:
                    port_list.append(pdict)
            
            # Flush old port entries for all domains that point to this IP
            for ad_obj in domains_for_ip:
                old_ports_count = Port.objects.filter(domain=ad_obj).count()
                if old_ports_count > 0:
                    Port.objects.filter(domain=ad_obj).delete()
                    self.stdout.write(f"Flushed {old_ports_count} old port entries for {ad_obj.value}")

            # Process the results and save to database for each domain
            open_ports_cnt = 0
            for port_entry in port_list:
                if port_entry["status"] == "open":
                    open_ports_cnt += 1
                    
                    # Create port entries for all domains that point to this IP
                    for ad_obj in domains_for_ip:
                        port_obj = Port.objects.create(
                            domain=ad_obj,
                            domain_name=ad_obj.value,
                            port=port_entry['port'],
                            scan_date=make_aware(datetime.now()),
                            banner=port_entry['banner'],
                            status=port_entry['status'],
                            product=port_entry['product'],
                            cpe=port_entry['cpe'],
                            raw=port_entry
                        )
            
            # Update last_scan_time for all domains that point to this IP
            for ad_obj in domains_for_ip:
                ad_obj.last_scan_time = make_aware(datetime.now())
                ad_obj.save()
            
            domain_names = [d.value for d in domains_for_ip]
            self.stdout.write(f"[+] {open_ports_cnt} ports found for IP {ip_address} (domains: {', '.join(domain_names)})")
            
        except Exception as error:
            domain_names = [d.value for d in domains_for_ip]
            self.stderr.write(f"Exception scanning IP {ip_address} (domains: {', '.join(domain_names)}): {str(error)}")

    def nmap_scan_domain(self, webaddress, ad_obj):
        self.stdout.write(f"Nmap scan starting for {webaddress}")
        try:
            port_list = []
            nm = nmap.PortScanner()
            nm.scan(
                webaddress,
                arguments='-F -Pn -sC -sV -T4 --version-light',
            )

            f = StringIO(nm.csv())
            r = csv.reader(f, delimiter=';')
            firstRow = None
            for row in r:
                # Skip the first row
                if row[0] == 'host':
                    firstRow = row
                    continue
                new_row = dict(zip(firstRow, row))
                pdict = {
                    'port': int(new_row['port']),
                    'banner': new_row['name'] + '::' + new_row['extrainfo'] + '::' + new_row['version'],
                    'status': new_row['state'],
                    'product': new_row['product'],
                    'cpe': new_row['cpe']
                }
                if pdict not in port_list:
                    port_list.append(pdict)
            
            # Flush old port entries for this domain
            old_ports_count = Port.objects.filter(domain=ad_obj).count()
            if old_ports_count > 0:
                Port.objects.filter(domain=ad_obj).delete()
                self.stdout.write(f"Flushed {old_ports_count} old port entries for {ad_obj.value}")

            # Process the results and save to database
            open_ports_cnt = 0
            for port_entry in port_list:
                if port_entry["status"] == "open":
                    open_ports_cnt += 1
                    port_obj = Port.objects.create(
                        domain=ad_obj,
                        domain_name=ad_obj.value,
                        port=port_entry['port'],
                        scan_date=make_aware(datetime.now()),
                        banner=port_entry['banner'],
                        status=port_entry['status'],
                        product=port_entry['product'],
                        cpe=port_entry['cpe'],
                        raw=port_entry
                    )
            
            ad_obj.last_scan_time = make_aware(datetime.now())
            ad_obj.save()
            self.stdout.write(f"[+] {open_ports_cnt} ports found for {ad_obj.value}")
            
        except Exception as error:
            self.stderr.write(f"Exception scanning domain {webaddress}: {str(error)}")
            