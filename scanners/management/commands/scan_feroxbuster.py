import json
import os
import socket
import ssl
import subprocess
import tempfile

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError

from findings.models import Endpoint
from assets.models import Asset
from project.models import Project
from scanners.scan_utils import resolve_uuids, add_common_scan_arguments


class Command(BaseCommand):
    help = 'Run Feroxbuster content discovery on web assets: ensure ports exist (nmap if needed), brute-force paths with Feroxbuster, store Endpoints.'

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, help='ID of the project to scan')
        add_common_scan_arguments(parser)
        parser.add_argument('--scope', type=str, help='Filter by scope (e.g., external, internal)', required=False)
        parser.add_argument('--new-assets', action='store_true', help='Only scan assets with empty last_scan_time')

    def handle(self, *args, **options):
        assets = self._get_assets_to_scan(**options)
        if not assets.exists():
            self.stdout.write('No assets to scan.')
            return

        if not getattr(settings, 'FEROXBUSTER_PATH', None):
            raise CommandError('FEROXBUSTER_PATH is not set in settings.')
        if not getattr(settings, 'FEROXBUSTER_WORDLIST', None):
            raise CommandError('FEROXBUSTER_WORDLIST is not set in settings.')

        if not os.path.isfile(settings.FEROXBUSTER_PATH):
            raise CommandError(
                f'Feroxbuster binary not found at {settings.FEROXBUSTER_PATH}. '
                'Install it with: brew install feroxbuster'
            )
        if not os.path.isfile(settings.FEROXBUSTER_WORDLIST):
            raise CommandError(
                f'Wordlist not found at {settings.FEROXBUSTER_WORDLIST}. '
                'Install SecLists with: brew install seclists'
            )

        for asset in assets:
            self._process_asset(asset, options)

    def _get_assets_to_scan(self, **kwargs):
        projectid = kwargs.get('projectid')
        scope_filter = kwargs.get('scope')
        new_assets_only = kwargs.get('new_assets')

        if projectid:
            try:
                project = Project.objects.get(id=projectid)
                qs = Asset.objects.filter(monitor=True, related_project=project)
            except Project.DoesNotExist:
                raise CommandError(f"Project with ID {projectid} does not exist.")
        else:
            qs = Asset.objects.filter(monitor=True)

        uuid_list = resolve_uuids(kwargs)
        if uuid_list:
            qs = qs.filter(uuid__in=uuid_list)
        if scope_filter:
            qs = qs.filter(scope=scope_filter)
        if new_assets_only:
            qs = qs.filter(last_scan_time__isnull=True)

        return qs

    def _detect_protocol(self, domain, port, timeout=3):
        """Detect if a port supports HTTPS or HTTP by attempting connections."""
        # Try HTTPS (TLS handshake) - don't verify certificate
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    return "https"
        except Exception:
            pass

        # Try HTTP (plain text request)
        try:
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % domain.encode())
                data = sock.recv(10)
                if data:
                    return "http"
        except Exception:
            pass

        return None

    def _get_web_root_urls(self, asset):
        """
        Detect web protocols (HTTP/HTTPS) on ports and return root URLs.
        Uses socket/SSL to probe each port and determine the protocol.
        """
        ports = asset.port_set.all()
        if not ports.exists():
            return []

        urls = []
        for port in ports:
            banner_lower = (port.banner or '').lower()
            if 'http' in banner_lower or 'ssl' in banner_lower:
                protocol = self._detect_protocol(asset.value, port.port)
                if protocol:
                    urls.append(f"{protocol}://{asset.value}:{port.port}")

        return urls

    def _process_asset(self, asset, options):
        self.stdout.write(f'Asset: {asset.value} ({asset.uuid})')

        # Ensure we have ports; run nmap if none
        if not asset.port_set.exists():
            self.stdout.write('  No ports found; running nmap.')
            call_command(
                'scan_nmap',
                uuids=asset.uuid,
                projectid=options.get('projectid'),
            )
            asset.refresh_from_db()

        root_urls = self._get_web_root_urls(asset)
        if not root_urls:
            self.stdout.write('  No web ports (http/https/ssl); skipping.')
            return

        self.stdout.write(f'  Root URLs: {len(root_urls)}')

        # Run Feroxbuster on root URLs
        discovered_urls = self._run_feroxbuster(root_urls)
        self.stdout.write(f'  Feroxbuster discovered: {len(discovered_urls)} URLs')

        # Delete existing endpoints for this asset, then create new ones
        deleted_count = Endpoint.objects.filter(asset=asset).delete()[0]
        self.stdout.write(f'  Deleted {deleted_count} existing endpoint(s)')

        # Merge root + discovered and create Endpoint records
        all_urls = list(dict.fromkeys(root_urls + discovered_urls))
        created = 0
        for url in all_urls:
            url = (url or '').strip()
            if not url:
                continue
            Endpoint.objects.create(
                url=url,
                asset=asset,
                technologies='',
            )
            created += 1

        self.stdout.write(f'  Endpoints created: {created}')

    def _run_feroxbuster(self, urls):
        """Run Feroxbuster with --stdin input and --json output; return list of discovered URLs."""
        feroxbuster_path = settings.FEROXBUSTER_PATH
        wordlist = settings.FEROXBUSTER_WORDLIST
        if not feroxbuster_path or not wordlist:
            self.stdout.write('  FEROXBUSTER_PATH/WORDLIST not set; skipping Feroxbuster.')
            return []

        out_fd, out_path = tempfile.mkstemp(suffix='.json', prefix='feroxbuster_')
        os.close(out_fd)

        try:
            cmd = [
                feroxbuster_path,
                '--stdin',
                '-w', wordlist,
                '-o', out_path,
                '--json',
                '-k',
                '-q',
                '-f',
                '-d', '2',
                '-t', '10',
                '-s', '200,204,301,302,307,308,401,403,405,500,503',
            ]

            result = subprocess.run(
                cmd,
                input='\n'.join(urls),
                capture_output=True,
                text=True,
            )

            discovered = []
            if os.path.exists(out_path):
                with open(out_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            url = obj.get('url')
                            if url:
                                discovered.append(url)
                        except (json.JSONDecodeError, TypeError):
                            pass

            return discovered
        except subprocess.TimeoutExpired:
            self.stdout.write(self.style.WARNING('  Feroxbuster timed out.'))
            return []
        except FileNotFoundError:
            self.stdout.write(self.style.WARNING(f'  Feroxbuster not found at {feroxbuster_path}.'))
            return []
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'  Feroxbuster error: {e}'))
            return []
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass