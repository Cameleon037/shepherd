from html.parser import HTMLParser

from django.template.loader import render_to_string
from django.test import SimpleTestCase
from django.urls import reverse


class TableMarkupParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tables = {}
        self.elements = []
        self.table_id = None
        self.in_header = False
        self.header_cells = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.elements.append((tag, attrs))
        if tag == "table":
            self.table_id = attrs.get("id")
        elif tag == "thead":
            self.in_header = True
        elif tag == "tr" and self.in_header:
            self.header_cells = 0
        elif tag == "th" and self.in_header:
            if self.header_cells is None:
                raise AssertionError("Table header cells must be inside a row")
            self.header_cells += 1

    def handle_endtag(self, tag):
        if tag == "tr" and self.in_header:
            self.tables.setdefault(self.table_id, []).append(self.header_cells)
            self.header_cells = None
        elif tag == "thead":
            self.in_header = False
        elif tag == "table":
            self.table_id = None


class TablePresentationTests(SimpleTestCase):
    tables = {
        "assets/list_assets.html": {"table_list_assets": 12},
        "assets/list_ignored_suggestions.html": {"table_list_ignored_suggestions": 8},
        "assets/list_suggestions.html": {
            "table_list_domain_suggestions": 14,
            "table_list_second_level_domain_suggestions": 14,
            "table_list_starreddomain_suggestions": 14,
            "table_list_ipaddress_suggestions": 12,
        },
        "findings/list_findings.html": {"table_list_findings": 11},
        "findings/list_data_leaks.html": {"table_list_findings": 8},
        "findings/list_dns_records.html": {"table_list_dns_records": 6},
        "findings/list_nmap_results.html": {"table_list_ports": 6},
        "findings/list_screenshots.html": {"table_list_httpx_results": 9},
        "findings/list_web_endpoints.html": {
            "table_assets": 4,
            "table_asset_endpoints": 6,
            "table_search_results": 6,
        },
        "jobs/list_jobs.html": {"table_list_jobs": 6},
        "jobs/list_scheduled_jobs.html": {"table_list_scheduled_jobs": 6},
        "keywords/list_keywords.html": {"table_list_keywords": 6, "table_suppliers": 5},
        "project/list_projects.html": {"table_list_projects": 5},
    }

    def render(self, template):
        html = render_to_string(template, {"projectid": 1, "csrf_token": "test-token"})
        parser = TableMarkupParser()
        parser.feed(html)
        return html, parser

    def test_table_schemas_and_filter_rows_remain_aligned(self):
        for template, tables in self.tables.items():
            with self.subTest(template=template):
                _, parser = self.render(template)
                for table_id, count in tables.items():
                    self.assertIn(table_id, parser.tables)
                    self.assertTrue(parser.tables[table_id])
                    self.assertTrue(all(cells == count for cells in parser.tables[table_id]))

    def test_selection_actions_start_disabled(self):
        for template in self.tables:
            with self.subTest(template=template):
                _, parser = self.render(template)
                for tag, attrs in parser.elements:
                    if "data-selection-action" in attrs or "data-clear-selection" in attrs:
                        self.assertEqual(tag, "button")
                        self.assertEqual(attrs.get("type"), "button")
                        self.assertIn("disabled", attrs)
                    if attrs.get("id") in {"btn-burp-scan", "clear-endpoint-selection"}:
                        self.assertIn("disabled", attrs)

    def test_default_columns_for_findings_assets_and_suggestions(self):
        asset_columns = 'value,vulns,tag,source,description,creation_time,registrant_info'
        defaults = {
            'assets/list_assets.html': asset_columns,
            'assets/list_suggestions.html': asset_columns,
            'assets/list_ignored_suggestions.html': asset_columns,
            'findings/list_findings.html': 'asset_name,name,description,source,severity,status,scan_date',
        }
        for template, expected in defaults.items():
            with self.subTest(template=template):
                _, parser = self.render(template)
                tables = [attrs for tag, attrs in parser.elements if tag == 'table']
                self.assertEqual(len(tables), len(self.tables[template]))
                for table in tables:
                    self.assertEqual(table.get('data-default-columns'), expected)

    def test_shared_details_dialog_and_styles(self):
        for template in self.tables:
            with self.subTest(template=template):
                html, parser = self.render(template)
                dialogs = [attrs for _, attrs in parser.elements if attrs.get("id") == "table-cell-details-modal"]
                self.assertEqual(len(dialogs), 1)
                self.assertEqual(dialogs[0].get("role"), "dialog")
                self.assertEqual(dialogs[0].get("aria-labelledby"), "table-cell-details-title")
                self.assertNotIn("<style>", html)
                self.assertNotIn("loading.gif", html)
                self.assertNotIn("// Selected Actions", html)
                self.assertNotIn("// General Actions", html)

    def test_grouping_choices_are_configured_without_replacing_endpoint_asset_groups(self):
        for template in self.tables:
            with self.subTest(template=template):
                _, parser = self.render(template)
                for tag, attrs in parser.elements:
                    if tag != 'table' or attrs.get('id') not in self.tables[template]:
                        continue
                    if attrs.get('id') == 'table_search_results':
                        self.assertNotIn('data-group-columns', attrs)
                    else:
                        self.assertTrue(attrs.get('data-group-columns'))
                    if template == 'findings/list_findings.html':
                        self.assertIn('asset_name', attrs['data-group-columns'].split(','))

    def test_asset_detail_tooltips_use_the_shared_route_configuration(self):
        for template in [*self.tables, "dashboard/dashboard.html"]:
            with self.subTest(template=template):
                _, parser = self.render(template)
                body = next(attrs for tag, attrs in parser.elements if tag == "body")
                self.assertEqual(
                    body.get("data-asset-details-url"),
                    reverse("assets:view_asset", kwargs={"uuid": "__UUID__"}),
                )

    def test_asset_screenshot_links_open_the_url_in_a_new_tab(self):
        url = "https://example.com/path?a=1&b=2"
        html = render_to_string("assets/view_asset.html", {
            "projectid": 1,
            "csrf_token": "test-token",
            "screenshots": [{"url": url, "screenshot_base64": "example"}],
        })
        parser = TableMarkupParser()
        parser.feed(html)
        links = [attrs for tag, attrs in parser.elements if tag == "a" and attrs.get("href") == url]
        self.assertEqual(len(links), 2)
        for link in links:
            self.assertEqual(link.get("target"), "_blank")
            self.assertIn("noopener", link.get("rel", ""))
