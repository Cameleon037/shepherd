import time
from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = "Create a dummy job"

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def handle(self, *args, **kwargs):
        # Filter suggestions by project ID if provided
        project_filter = {}
        if kwargs['projectid']:
            project_filter['related_project__id'] = kwargs['projectid']

        for i in range(10):
            
            self.stdout.write(f"Project id: {kwargs['projectid']} has waited: {i} seconds so far.")
            time.sleep(1)