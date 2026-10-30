import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django_celery_beat.models import IntervalSchedule, PeriodicTask
from rest_framework.test import APIClient

from assets.models import Asset
from findings.models import DNSRecord, Endpoint, Finding, Port, Screenshot
from jobs.models import Job
from keywords.models import Keyword
from project.models import Project
from api.utils import apply_table_grouping


@override_settings(ALLOWED_HOSTS=['testserver'])
class TableGlobalSearchTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = get_user_model().objects.create_superuser('tester', password='test')
        self.client.force_authenticate(self.user)
        self.project = Project.objects.create(projectname='Search tests', description='Contains Needle here')
        self.other_project = Project.objects.create(projectname='Other project')
        for project in (self.project, self.other_project):
            for term in ('needle', 'other'):
                asset = Asset.objects.create(
                    uuid=str(uuid.uuid4()), value=f'{term}.example.com',
                    related_project=project, creation_time=timezone.now(),
                    monitor=True, source='shared', tag=f'{term}-tag',
                )
                keyword = Keyword.objects.create(
                    related_project=project, keyword=term, description=f'Contains {term} here',
                )
                DNSRecord.objects.create(
                    related_project=project, related_asset=asset, record_type='TXT',
                    record_value=f'{term} shared', ttl=300,
                )
                Endpoint.objects.create(
                    asset=asset, url=f'https://{project.pk}-{term}.example.com/',
                    technologies='shared', response_size=123 if term == 'needle' else 456,
                )
                Screenshot.objects.create(
                    asset=asset, url=f'https://{project.pk}-{term}.example.com/', technologies='shared',
                )
                Port.objects.create(asset=asset, port=443, banner=f'{term} shared')
                Finding.objects.create(asset=asset, name=f'{term} shared', type='vulnerability')
                Finding.objects.create(keyword=keyword, name=f'{term} shared', type='data_leak', source='git-hound')
                Job.objects.create(
                    related_project=project, command=f'{term}_command', args='shared',
                    user=self.user, output='not searchable output',
                )
        interval = IntervalSchedule.objects.create(every=7, period=IntervalSchedule.MINUTES)
        for term in ('needle', 'other'):
            PeriodicTask.objects.create(name=term, task='shared', interval=interval)

    def search(self, route, value, **params):
        kwargs = {} if route in ('projects', 'list_scheduled_jobs') else {'projectid': self.project.pk}
        response = self.client.get(reverse('api:' + route, kwargs=kwargs), {
            'search[value]': value, 'length': 100, **params,
        }, secure=True)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_global_search_on_every_table_endpoint(self):
        routes = [
            'projects', 'list_suggestions', 'list_assets', 'list_dns_records',
            'list_endpoints', 'list_keywords', 'list_ports', 'list_all_findings',
            'list_data_leaks', 'list_jobs', 'list_screenshots', 'list_scheduled_jobs',
        ]
        for route in routes:
            params = {'selection': 'monitored'} if route == 'list_assets' else {}
            for value, count in [(' NEEDLE ', 1), ('needle, !other', 1), ('needle, missing', 0), ('', 2)]:
                with self.subTest(route=route, value=value):
                    self.assertEqual(self.search(route, value, **params)['count'], count)

    def test_global_search_matches_descriptions_not_only_prefixes(self):
        for route in ('projects', 'list_keywords'):
            with self.subTest(route=route):
                self.assertEqual(self.search(route, 'contains, needle')['count'], 1)

    def test_asset_search_includes_tags(self):
        self.assertEqual(self.search('list_assets', 'needle-tag', selection='monitored')['count'], 1)

    def test_endpoint_search_combines_project_and_table_search(self):
        self.assertEqual(self.search('list_endpoints', '!needle', search='needle')['count'], 0)
        self.assertEqual(self.search('list_endpoints', 'shared', search='needle')['count'], 1)

    def test_endpoint_column_search_uses_each_tables_schema(self):
        for index in (2, 3):
            with self.subTest(index=index):
                params = {
                    'columns[0][data]': 'url', f'columns[{index}][data]': 'technologies',
                    f'columns[{index}][search][value]': 'missing',
                }
                self.assertEqual(self.search('list_endpoints', '', **params)['count'], 0)

    def test_scheduled_search_matches_displayed_schedule_and_enabled_state(self):
        self.assertEqual(self.search('list_scheduled_jobs', '7 minutes, true')['count'], 2)
        self.assertEqual(self.search('list_scheduled_jobs', '!7 minutes')['count'], 0)

    def test_job_list_omits_output_and_does_not_search_it(self):
        rows = self.search('list_jobs', '')['results']
        self.assertTrue(all('output' not in row for row in rows))
        self.assertEqual(self.search('list_jobs', 'not searchable output')['count'], 0)

    def test_suggestions_use_the_same_vulnerability_badges_as_assets(self):
        asset = Asset.objects.get(related_project=self.project, value='needle.example.com')
        Finding.objects.create(asset=asset, severity='high')
        Finding.objects.create(asset=asset, severity='high', ignore=True)
        Finding.objects.create(asset=asset, severity='high', status='fixed')
        suggestion = self.search('list_suggestions', 'needle')['results'][0]
        inventory = self.search('list_assets', 'needle', selection='monitored')['results'][0]
        self.assertEqual(suggestion['vulns'], inventory['vulns'])
        self.assertIn('label-danger">1</span>', suggestion['vulns'])

    def test_suggestion_column_filters_follow_the_table_schema(self):
        for index, field, term in [(5, 'tag', 'needle-tag'), (8, 'owner', 'missing')]:
            with self.subTest(index=index, field=field):
                result = self.search('list_suggestions', '', **{
                    'columns[0][data]': 'uuid',
                    f'columns[{index}][data]': field,
                    f'columns[{index}][search][value]': term,
                })
                self.assertEqual(result['count'], 1 if field == 'tag' else 0)

    def test_findings_grouping_orders_before_pagination_and_preserves_row_sort(self):
        assets = list(Asset.objects.filter(related_project=self.project).order_by('value'))
        for asset, name in [(assets[0], 'B'), (assets[1], 'D'), (assets[0], 'A'), (assets[1], 'C')]:
            Finding.objects.create(asset=asset, asset_name=asset.value, name='group test ' + name)
        params = {
            'group_by': 'asset_name', 'length': 2,
            'order[0][column]': '2', 'order[0][dir]': 'desc', 'columns[2][data]': 'name',
        }
        page_one = self.search('list_all_findings', 'group test', **params)
        page_two = self.search('list_all_findings', 'group test', start=2, **params)
        self.assertEqual(page_one['count'], 4)
        self.assertEqual([row['name'] for row in page_one['results']], ['group test B', 'group test A'])
        self.assertEqual([row['name'] for row in page_two['results']], ['group test D', 'group test C'])
        self.assertTrue(all(row['asset_name'] == assets[0].value for row in page_one['results']))
        self.assertTrue(all(row['asset_name'] == assets[1].value for row in page_two['results']))
        params['group_by'] = ''
        ungrouped = self.search('list_all_findings', 'group test', **params)
        self.assertEqual([row['name'] for row in ungrouped['results']], ['group test D', 'group test C'])

    def test_grouping_supported_table_responses_preserves_scope_and_counts(self):
        for route, field in [
            ('projects', 'projectname'), ('list_suggestions', 'source'), ('list_assets', 'tag'),
            ('list_dns_records', 'record_type'), ('list_endpoints', 'technologies'),
            ('list_keywords', 'enabled'), ('list_ports', 'port'), ('list_all_findings', 'severity'),
            ('list_data_leaks', 'keyword'), ('list_jobs', 'username'),
            ('list_screenshots', 'asset_source'), ('list_scheduled_jobs', 'schedule'),
        ]:
            with self.subTest(route=route):
                params = {'selection': 'monitored'} if route == 'list_assets' else {}
                self.assertEqual(self.search(route, '', group_by=field, **params)['count'], 2)

    def test_list_grouping_is_stable_with_missing_and_boolean_values(self):
        rows = [{'enabled': True, 'name': 'a'}, {'enabled': False, 'name': 'b'},
                {'enabled': True, 'name': 'c'}, {'enabled': False, 'name': 'd'}]
        grouped = apply_table_grouping(rows, 'enabled')
        self.assertEqual([row['name'] for row in grouped], ['b', 'd', 'a', 'c'])
        self.assertIs(apply_table_grouping(rows, 'output'), rows)

    def test_unrecognized_grouping_fields_are_ignored(self):
        for field in ('not_a_field', 'user__password', '-command'):
            with self.subTest(field=field):
                self.assertEqual(self.search('list_jobs', '', group_by=field)['count'], 2)
