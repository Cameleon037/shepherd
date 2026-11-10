from django.core.management.base import BaseCommand

from assets.models import Asset


class Command(BaseCommand):
    help = ('Classify every asset: assign category and reset type/subtype '
            '(fixes records created before central classification).')

    def add_arguments(self, parser):
        parser.add_argument('--projectid', type=int, required=False,
                            help='Only sort this project; default: all projects')

    def handle(self, *args, **options):
        queryset = Asset.objects.all()
        if options['projectid']:
            queryset = queryset.filter(related_project_id=options['projectid'])

        reclassified = 0
        recategorized = 0
        category_counts = {}
        for asset in queryset:
            old_type, old_subtype, old_category = asset.type, asset.subtype, asset.category
            asset.set_classification()
            if (asset.type, asset.subtype) != (old_type, old_subtype):
                reclassified += 1
            if asset.category != old_category:
                recategorized += 1
            if (asset.type, asset.subtype, asset.category) != (old_type, old_subtype, old_category):
                asset.save(update_fields=['type', 'subtype', 'category'])
            category_counts[asset.category or '(uncategorized)'] = \
                category_counts.get(asset.category or '(uncategorized)', 0) + 1

        self.stdout.write(f'sort_assets: {queryset.count()} assets, '
                          f'{reclassified} type/subtype reset, {recategorized} categorized')
        for name in sorted(category_counts, key=lambda c: -category_counts[c]):
            self.stdout.write(f'  {name}: {category_counts[name]}')
