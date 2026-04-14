import html
import tempfile
from urllib.parse import urlencode, quote_plus
import subprocess
from project.models import Project, Keyword, Asset
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
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def handle(self, *args, **options):

        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            for kw in prj.keyword_set.all():

                if not kw.enabled:
                    continue

                keyword = html.unescape(kw.keyword)
                if kw.ktype == "porch-pirate_keyword":
                    self.stdout.write("[+] Porch-pirate search: {}".format(keyword))
                    self.porchpirate_scan(kw, prj)

    def porchpirate_workspace_scan(self, workspace_id):
        public_handle = ''
        command = ['porch-pirate', '-w', workspace_id, '--raw']
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                self.stderr.write(f'[+] Error scanning workspace {workspace_id}: {result.stderr}')
                return
            
            output = result.stdout
            json_output = json.loads(output)

            try:
                public_handle = json_output["data"]["profileInfo"]["publicHandle"]
            except Exception as e:
                self.stderr.write(f'    [+] Could not fetch publicHandle: {e}')

        except Exception as error:
            self.stderr.write(f'    [+] Error running porch-pirate workspace scan: {error}')
        
        return public_handle

    def porchpirate_scan(self, kw, prj):
    
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as out_f:
            # Print the file location for debugging
            # self.stdout.write(f"[DEBUG] Output file location: {out_f.name}")

            # Build the Porch-pirate command
            keyword = html.unescape(kw.keyword)
            command = ['porch-pirate', '-s', keyword, '-l', '25', '--raw']

            # Trigger Porch-pirate scan and store output in the file
            result = subprocess.run(command, stdout=out_f, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                self.stderr.write(f'[+] Error scanning keyword {keyword}: {result.stderr}')
                return
        
            try:
                out_f.seek(0)
                output_content = out_f.read()
                # Find the first '{' that starts a JSON object after a newline
                match = re.search(r'({.*)', output_content, re.DOTALL)
                raw_output = match.group(1)

                json_output = json.loads(raw_output)
                # print(json_output)
                if json_output["meta"]["total"]["workspace"] > 0:
                    self.stdout.write(f'[+] Workspaces found: {json_output["meta"]["total"]["workspace"]}')
                
                    for entry in json_output["data"]:
                        if entry["document"]["entityType"] == "workspace":
                            workspace_id = entry["document"]["id"]
                            workspace_name = entry["document"]["name"]
                            self.stdout.write(f'    [+] Workspace id: {workspace_id}')
                            self.stdout.write(f'    [+] Workspace name: {workspace_name}')
                            public_handle = self.porchpirate_workspace_scan(workspace_id)
                            self.stdout.write(f'    [+] Public handle URL: {public_handle}')

                            # Store/update by URL to avoid duplicate leak entries.
                            Finding.objects.update_or_create(
                                source='porch-pirate',
                                url=public_handle,
                                defaults={
                                    'keyword': kw,
                                    'name': workspace_name,
                                    'type': 'workspace',
                                    'description': 'Check if the public workspace contains sensitive data',
                                    'scan_date': make_aware(datetime.now()),
                                    'last_seen': make_aware(datetime.now()),
                                },
                            )
                                            
            except Exception as error:
                self.stderr.write(f'[+] Error no valid JSON found in the output: {error}')
                return
            