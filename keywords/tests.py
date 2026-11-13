from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from keywords.models import Keyword, group_keywords_by_text
from keywords.services.miner import live_keyword_texts
from project.models import Project

# DataTables parameter set the Keywords table sends (field names, not indices, are what
# the API resolves column searches and ordering by). Actions is the first column.
LIST_PARAMS = ('?selection=all&length=25&start=0'
               '&columns[0][data]=id&columns[1][data]=keyword&columns[2][data]=ktypes'
               '&columns[3][data]=enabled&columns[4][data]=description'
               '&columns[5][data]=creation_time')


@override_settings(SECURE_SSL_REDIRECT=False)
class KeywordTextStateTests(TestCase):
    """Keyword enable/disable is text-level: every row of one text shares one state.

    Fixture texts are chosen so alphabetical order differs from state order:
    zz-live (both types on), mm-mixed (one on, one off), aa-off (off).
    """

    def setUp(self):
        user = User.objects.create_user('kwstate')
        user.is_superuser = True
        user.save()
        self.client.force_login(user)
        self.prj = Project.objects.create(projectname='__kw_state__')
        Keyword.objects.create(related_project=self.prj, keyword='zz-live', ktype='crtsh_domain', enabled=True)
        Keyword.objects.create(related_project=self.prj, keyword='zz-live', ktype='crtsh_brand', enabled=True)
        Keyword.objects.create(related_project=self.prj, keyword='mm-mixed',
                               ktype='crtsh_domain', enabled=True)
        self.mixed_off = Keyword.objects.create(related_project=self.prj, keyword='mm-mixed',
                                                ktype='shodan_keyword', enabled=False)
        Keyword.objects.create(related_project=self.prj, keyword='aa-off',
                               ktype='crtsh_domain', enabled=False)

    def groups(self):
        return {g['keyword']: g for g in group_keywords_by_text(self.prj.keyword_set.all())}

    def list_all(self, extra=''):
        url = reverse('api:list_keywords', kwargs={'projectid': str(self.prj.id)})
        response = self.client.get(url + LIST_PARAMS + extra)
        self.assertEqual(response.status_code, 200)
        return response.json()['results']

    def test_group_state_reports_counts_not_only_the_and(self):
        mixed = self.groups()['mm-mixed']
        self.assertFalse(mixed['enabled'])          # not every type is live
        self.assertTrue(mixed['any_enabled'])       # but some type is
        self.assertEqual((mixed['enabled_count'], mixed['type_count']), (1, 2))
        self.assertFalse(self.groups()['aa-off']['any_enabled'])
        self.assertTrue(self.groups()['zz-live']['enabled'])

    def test_state_blocks_pin_the_list_regardless_of_alphabetical_order(self):
        self.assertEqual([g['keyword'] for g in self.list_all()], ['zz-live', 'mm-mixed', 'aa-off'])
        # Sorting by keyword (index 1) desc still keeps the state blocks in front.
        by_kw = self.list_all('&order[0][column]=1&order[0][dir]=desc')
        self.assertEqual([g['keyword'] for g in by_kw], ['zz-live', 'mm-mixed', 'aa-off'])
        # An explicit Enabled-column sort (index 3) may flip the blocks.
        by_enabled = self.list_all('&order[0][column]=3&order[0][dir]=desc')
        self.assertEqual([g['keyword'] for g in by_enabled], ['aa-off', 'mm-mixed', 'zz-live'])

    def test_list_carries_the_counts_the_switch_renders(self):
        mixed = next(g for g in self.list_all() if g['keyword'] == 'mm-mixed')
        self.assertEqual((mixed['enabled_count'], mixed['type_count'], mixed['any_enabled']), (1, 2, True))

    def test_column_search_resolves_by_field_not_by_column_position(self):
        # Actions is index 0, so Enabled sits at 3 and Types at 2 in this layout.
        enabled_only = self.list_all('&columns[3][search][value]=true')
        self.assertEqual({g['keyword'] for g in enabled_only}, {'zz-live', 'mm-mixed'})
        types_hit = self.list_all('&columns[2][search][value]=shodan')
        self.assertEqual([g['keyword'] for g in types_hit], ['mm-mixed'])
        self.assertIn('crtsh_domain', types_hit[0]['ktypes'])  # the group was not split
        keyword_hit = self.list_all('&columns[1][search][value]=!mm')
        self.assertEqual({g['keyword'] for g in keyword_hit}, {'zz-live', 'aa-off'})

    def test_miner_inherits_the_state_of_an_existing_text(self):
        self.assertEqual(live_keyword_texts(self.prj), {'zz-live', 'mm-mixed'})

    def test_bulk_enable_resolves_a_mixed_text_to_enabled(self):
        url = reverse('api:bulk_keywords', kwargs={'projectid': str(self.prj.id)})
        response = self.client.post(url, {'action': 'enable', 'id[]': str(self.mixed_off.id)})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(k.enabled for k in Keyword.objects.filter(
            related_project=self.prj, keyword='mm-mixed')))
