from django.core.management.base import BaseCommand, CommandError

from project.models import Project
from keywords.services import miner


class Command(BaseCommand):
    help = ('Mine candidate keywords (with evidence) for a project from one seed URL. '
            'Brand-new keyword texts are stored as DISABLED rows; nothing of theirs is '
            'scanned until they are enabled on the Keywords page. A new type of an '
            'existing keyword inherits that keyword\'s enabled state.')

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, required=True,
                            help='Project to mine keywords for')
        parser.add_argument('--url', type=str, required=True,
                            help='Seed URL or domain (e.g. example.com or https://example.com)')
        parser.add_argument('--max-tokens', type=int, default=25,
                            help='Max mined token candidates per keyword type (default 25)')
        parser.add_argument('--dry-run', action='store_true',
                            help='Report suggestions without creating keyword rows')

    def handle(self, *args, **options):
        projectid = options['projectid']
        try:
            project = Project.objects.get(id=projectid)
        except Project.DoesNotExist:
            raise CommandError(f'Project with ID {projectid} does not exist.')

        seed = miner.seed_domain(options['url'])
        if not seed:
            raise CommandError(f"Could not derive a domain from {options['url']}")

        self.stdout.write(f'[+] Mining keywords for project "{project.projectname}" from seed {seed}')
        created, skipped, suggested, report = miner.mine(
            project, seed, max_tokens=options['max_tokens'], dry_run=options['dry_run'])

        for line in report:
            self.stdout.write(line)

        self.stdout.write(
            f'[+] Keyword miner: {created} keyword rows created | '
            f'{skipped} already existed | {suggested} suggestions total '
            f'(new texts disabled for review; rows reported as "enabled with existing '
            f'keyword" inherited an already-live keyword)'
        )
        if options['dry_run']:
            self.stdout.write('[+] (dry run: nothing was written)')
