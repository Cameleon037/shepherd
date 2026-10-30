import json
import uuid
from unittest.mock import patch

from django.contrib.admin import AdminSite, ModelAdmin
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from api.serializer import SuggestionSerializer
from assets.classification import classify_asset
from assets.forms import AddAssetForm, AddSuggestionForm
from assets.models import Asset
from assets.utils import upload_domains_from_file
from project.models import Project
from scanners.management.commands.import_crtsh import Command as CrtshCommand


class AssetClassificationTests(SimpleTestCase):
    def test_types_and_subtypes(self):
        cases = [
            ('example.com', 'domain', 'domain'),
            ('api.example.com', 'domain', 'subdomain'),
            ('example.co.uk', 'domain', 'domain'),
            ('api.example.co.uk', 'domain', 'subdomain'),
            (' EXAMPLE.COM. ', 'domain', 'domain'),
            ('API.EXAMPLE.COM.', 'domain', 'subdomain'),
            ('xn--bcher-kva.de', 'domain', 'domain'),
            ('api.xn--bcher-kva.de', 'domain', 'subdomain'),
            ('localhost', 'domain', 'domain'),
            ('host.corp.internal', 'domain', 'subdomain'),
            ('*.example.com', 'starred_domain', 'domain'),
            ('*.api.example.co.uk', 'starred_domain', 'subdomain'),
            ('api.*.example.com', 'starred_domain', 'subdomain'),
            ('192.0.2.1', 'ip', ''),
            ('2001:db8::1', 'ip', ''),
            ('[2001:db8::1]', 'ip', ''),
            ('https://example.com', 'url', ''),
            ('https://api.example.com/path?a=1', 'url', ''),
            ('http://192.0.2.1:8080/', 'url', ''),
            ('https://[2001:db8::1]/', 'url', ''),
            ('ftp://example.com/file', 'url', ''),
            ('//example.com/path', 'url', ''),
            ('example.com/path', 'url', ''),
            ('-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----', 'certificate', ''),
        ]
        for value, asset_type, subtype in cases:
            with self.subTest(value=value):
                self.assertEqual(classify_asset(value), (asset_type, subtype))

    def test_incorrect_type_hints_do_not_override_the_value(self):
        self.assertEqual(classify_asset('example.co.uk', 'ip'), ('domain', 'domain'))
        self.assertEqual(classify_asset('192.0.2.1', 'domain'), ('ip', ''))
        self.assertEqual(classify_asset('example.com', 'starred_domain'), ('domain', 'domain'))

    def test_explicit_certificate_context_is_preserved(self):
        self.assertEqual(classify_asset('example.com', 'certificate'), ('certificate', ''))


class AssetCreationTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(projectname='Classification tests')

    def asset_data(self, value, **kwargs):
        return {
            'uuid': str(uuid.uuid4()),
            'value': value,
            'related_project': self.project,
            'creation_time': timezone.now(),
            **kwargs,
        }

    def assert_classification(self, asset, asset_type, subtype):
        asset.refresh_from_db()
        self.assertEqual((asset.type, asset.subtype), (asset_type, subtype))

    def test_direct_save_and_manager_create(self):
        asset = Asset(**self.asset_data('2001:db8::1', subtype='host'))
        asset.save(force_insert=True)
        self.assert_classification(asset, 'ip', '')
        asset = Asset.objects.create(**self.asset_data('api.example.co.uk', type='ip', subtype='domain'))
        self.assert_classification(asset, 'domain', 'subdomain')

    def test_get_or_create_and_update_or_create(self):
        for method, value, expected in [
            ('get_or_create', '*.example.com', ('starred_domain', 'domain')),
            ('update_or_create', 'https://example.com/path', ('url', '')),
        ]:
            with self.subTest(method=method):
                data = self.asset_data(value, type='domain', subtype='subdomain')
                asset_id = data.pop('uuid')
                asset, created = getattr(Asset.objects, method)(uuid=asset_id, defaults=data)
                self.assertTrue(created)
                self.assert_classification(asset, *expected)

    def test_existing_duplicates_and_unrelated_updates_are_unchanged(self):
        asset = Asset.objects.create(**self.asset_data('example.com', source='original', monitor=True))
        Asset.objects.filter(pk=asset.pk).update(subtype='legacy')
        same_asset, created = Asset.objects.get_or_create(uuid=asset.uuid, defaults={'value': '192.0.2.1'})
        self.assertFalse(created)
        same_asset.ignore = True
        same_asset.save(update_fields=['ignore'])
        self.assert_classification(same_asset, 'domain', 'legacy')
        self.assertEqual(same_asset.value, 'example.com')
        self.assertEqual(same_asset.source, 'original')
        self.assertTrue(same_asset.monitor)

    def test_bulk_create_including_a_generator_and_related_manager(self):
        assets = [
            Asset(**self.asset_data('192.0.2.1', subtype='host')),
            Asset(**self.asset_data('*.api.example.com', subtype='domain')),
        ]
        self.project.asset_set.bulk_create((asset for asset in assets), 100)
        self.assert_classification(assets[0], 'ip', '')
        self.assert_classification(assets[1], 'starred_domain', 'subdomain')

    def test_manual_forms(self):
        for form_class in (AddAssetForm, AddSuggestionForm):
            with self.subTest(form=form_class.__name__):
                form = form_class(data={
                    'value': 'api.example.co.uk', 'type': 'domain',
                    'subtype': 'domain', 'source': 'manual',
                })
                self.assertTrue(form.is_valid(), form.errors)
                asset = form.save(commit=False)
                asset.uuid = str(uuid.uuid4())
                asset.related_project = self.project
                asset.creation_time = timezone.now()
                asset.save(force_insert=True)
                self.assert_classification(asset, 'domain', 'subdomain')

    def test_admin_creation(self):
        asset = Asset(**self.asset_data('192.0.2.1', subtype='domain'))
        ModelAdmin(Asset, AdminSite()).save_model(None, asset, None, change=False)
        self.assert_classification(asset, 'ip', '')

    def test_serializer_creation(self):
        data = self.asset_data('https://example.com/path', type='domain', subtype='domain')
        data['related_project'] = self.project.pk
        serializer = SuggestionSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assert_classification(serializer.save(), 'url', '')

    def test_certificate_creation(self):
        asset = Asset.objects.create(**self.asset_data('example.com', type='certificate', subtype='domain'))
        self.assert_classification(asset, 'certificate', '')

    @patch('assets.utils.messages.success')
    @patch('assets.utils.threading.Thread')
    def test_file_upload_classifies_assets_without_changing_monitoring(self, thread, success):
        request = RequestFactory().post('/', {
            'domain_file': SimpleUploadedFile('assets.txt', (
                'api.example.co.uk\n192.0.2.1\n2001:db8::1\n'
                'https://example.com/path\n*.example.com\n'
            ).encode()),
        })
        request.user = None

        def process_synchronously():
            kwargs = thread.call_args.kwargs
            kwargs['target'](*kwargs['args'])

        thread.return_value.start.side_effect = process_synchronously
        upload_domains_from_file(request, self.project, 'assets:assets', monitor_new=True)
        for value, asset_type, subtype in [
            ('api.example.co.uk', 'domain', 'subdomain'),
            ('192.0.2.1', 'ip', ''),
            ('2001:db8::1', 'ip', ''),
            ('https://example.com/path', 'url', ''),
            ('*.example.com', 'starred_domain', 'domain'),
        ]:
            with self.subTest(value=value):
                asset = Asset.objects.get(value=value)
                self.assert_classification(asset, asset_type, subtype)
                self.assertEqual(asset.monitor, asset_type != 'starred_domain')
                self.assertEqual(asset.source, 'file_upload')

    @patch('scanners.management.commands.import_crtsh.requests.get')
    def test_crtsh_wildcard_does_not_make_the_parent_domain_a_wildcard(self, get):
        get.return_value.content = json.dumps([
            {'common_name': '*.api.example.co.uk', 'name_value': '*.api.example.co.uk'}
        ]).encode()
        CrtshCommand().crtsh_suggestion_population('https://crt.sh/', {}, None, self.project)
        wildcard = Asset.objects.get(value='*.api.example.co.uk')
        parent = Asset.objects.get(value='example.co.uk')
        self.assert_classification(wildcard, 'starred_domain', 'subdomain')
        self.assert_classification(parent, 'domain', 'domain')
