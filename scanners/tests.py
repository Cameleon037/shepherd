from django.test import TestCase

from scanners.management.commands.scan_ai_scribd import (
    Command,
    scribd_url_reject_reason,
)


class ScribdUrlGateTests(TestCase):
    def test_blocks_everything_off_allowlist(self):
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,steal",
            "blob:https://www.scribd.com/abc",
            "http://www.scribd.com/document/1",
            "https://evil.example/x",
            "https://evil-scribd.com/",
            "https://scribd.com.evil.example/",
            "https://sub.scribd.com.evil.example/x",
            "https://www.scribd.com@evil.example/",
            "https://www.scribd.com:8443/document/1",
            "not-a-url",
            "",
        ]:
            self.assertIsNotNone(scribd_url_reject_reason(bad), bad)

    def test_allows_plain_https_scribd(self):
        for good in [
            "https://www.scribd.com/document/123456/title",
            "https://scribd.com/",
            "https://WWW.SCRIBD.COM/doc",
            "https://html.scribd.com/1/image/0",
        ]:
            self.assertIsNone(scribd_url_reject_reason(good), good)


class ValidateFindingsTests(TestCase):
    def test_drops_exfil_urls_bad_severity_and_caps_length(self):
        cmd = Command()
        raw = [
            {"url": "https://www.scribd.com/document/1", "severity": "High",
             "name": " real leak ", "evidence": "x" * 3000},
            {"url": "https://exfil.example/?q=secret", "severity": "High",
             "name": "planted finding", "evidence": "y"},
            {"url": "https://www.scribd.com/document/2", "severity": "CRITICAL!!",
             "name": "bad severity"},
            "not-a-dict",
        ]
        kept = cmd.validate_findings(raw)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["url"], "https://www.scribd.com/document/1")
        self.assertEqual(kept[0]["name"], "real leak")
        self.assertEqual(len(kept[0]["evidence"]), 2000)
