import html
import json
import os
import subprocess
import tempfile
from datetime import datetime

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.timezone import make_aware

from findings.models import Finding
from project.models import Project
from project.scan_utils import add_common_scan_arguments


class Command(BaseCommand):
    help = "Run ghleaks scans for project keywords and store findings"

    def add_arguments(self, parser):
        parser.add_argument("--projectid", type=int, help="Filter by specific project ID")
        add_common_scan_arguments(parser)

    def handle(self, *args, **options):
        project_filter = {}
        if options.get("projectid"):
            project_filter["id"] = options["projectid"]

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")

            keywords = prj.keyword_set.filter(enabled=True, ktype="git-hound_keyword")
            for kw in keywords:
                keyword = html.unescape(kw.keyword)
                self.stdout.write(f"[+] ghleaks search: {keyword}")
                self.ghleaks_scan(kw, keyword)

    def ghleaks_scan(self, kw, keyword):
        ghleaks_token = getattr(settings, "GHLEAKS_TOKEN", "")
        ghleaks_working_dir = getattr(settings, "GHLEAKS_WORKING_DIR", None)
        ghleaks_binary = getattr(settings, "GHLEAKS_BINARY", "./ghleaks")
        ghleaks_debug = bool(getattr(settings, "GHLEAKS_DEBUG", False))

        if not ghleaks_token:
            self.stderr.write("[+] Missing GHLEAKS_TOKEN setting; skipping ghleaks scan.")
            return

        if ghleaks_working_dir and not os.path.isdir(ghleaks_working_dir):
            self.stderr.write(
                f"[+] GHLEAKS_WORKING_DIR does not exist: {ghleaks_working_dir}; skipping keyword {keyword}"
            )
            return

        report_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_report:
                report_path = temp_report.name

            command = [
                ghleaks_binary,
                "--query",
                keyword,
                "--token",
                ghleaks_token,
                "-r",
                report_path,
            ]

            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=ghleaks_working_dir,
            )

            stdout_preview = (result.stdout or "").strip()
            stderr_preview = (result.stderr or "").strip()
            report_exists = bool(report_path and os.path.exists(report_path))
            report_size = os.path.getsize(report_path) if report_exists else 0

            self.stdout.write(
                f"[+] ghleaks command finished for '{keyword}' "
                f"(exit_code={result.returncode}, report_exists={report_exists}, report_size={report_size} bytes)"
            )

            if ghleaks_debug:
                self.stdout.write(f"    [+] Command: {' '.join(command[:-1])} <report_path>")
                if stdout_preview:
                    self.stdout.write(f"    [+] stdout: {stdout_preview[:600]}")
                if stderr_preview:
                    self.stdout.write(f"    [+] stderr: {stderr_preview[:600]}")

            if result.returncode != 0 and not report_exists:
                self.stderr.write(
                    f"[+] Error scanning keyword {keyword}: exit_code={result.returncode}, "
                    f"stderr={stderr_preview[:400] or '<empty>'}"
                )
                return

            if not os.path.exists(report_path):
                self.stderr.write(f"[+] ghleaks report missing for keyword {keyword}.")
                return

            try:
                with open(report_path, "r", encoding="utf-8") as report_file:
                    report_data = json.load(report_file)
            except json.JSONDecodeError as error:
                report_snippet = ""
                try:
                    with open(report_path, "r", encoding="utf-8", errors="replace") as report_file:
                        report_snippet = report_file.read(800)
                except Exception:
                    report_snippet = "<could not read report for debug>"
                self.stderr.write(
                    f"[+] Invalid ghleaks JSON report for {keyword}: {error} | "
                    f"report_size={os.path.getsize(report_path)} bytes | preview={report_snippet}"
                )
                return

            findings = report_data.get("findings", [])
            if not isinstance(findings, list):
                self.stderr.write(
                    f"[+] Invalid ghleaks report structure for {keyword}: "
                    f"'findings' is {type(findings).__name__}, expected list."
                )
                return

            self.stdout.write(
                f"[+] Parsed ghleaks report for '{keyword}': "
                f"findings={len(findings)}, total_files={report_data.get('total_files', 'n/a')}, "
                f"duration={report_data.get('duration', 'n/a')}"
            )

            if not findings:
                self.stdout.write(f"    [+] No results found for {keyword}")
                return

            findings_count = 0
            skipped_without_url = 0
            for item in findings:
                file_url = item.get("github_url") or item.get("Link") or ""
                if not file_url:
                    skipped_without_url += 1
                    if ghleaks_debug:
                        self.stderr.write(
                            f"    [+] Skipping finding without URL. Keys: {list(item.keys())}"
                        )
                    continue

                rule_id = item.get("RuleID", "unknown-rule")
                description = item.get("Description", "Potential secret leak found")
                repository = item.get("repository", "")
                file_path = item.get("File", "")
                start_line = item.get("StartLine", "")
                match_string = item.get("Match", "")

                if match_string and len(match_string) > 120:
                    match_string = f"{match_string[:120]}..."

                finding_name = f"{description} in {repository}" if repository else description
                severity = self._determine_severity(rule_id, description)

                description_parts = [f"Rule: {rule_id}"]
                if repository:
                    description_parts.append(f"Repository: {repository}")
                if file_path:
                    description_parts.append(f"File: {file_path}")
                if start_line:
                    description_parts.append(f"Line: {start_line}")
                if match_string:
                    description_parts.append(f"Match: {match_string}")
                finding_description = " | ".join(description_parts)

                finding_obj, created = Finding.objects.update_or_create(
                    source="ghleaks",
                    url=file_url,
                    defaults={
                        "keyword": kw,
                        "name": finding_name,
                        "type": "data_leak",
                        "severity": severity,
                        "description": finding_description,
                        "scan_date": make_aware(datetime.now()),
                        "last_seen": make_aware(datetime.now()),
                    },
                )
                findings_count += 1

                if created:
                    self.stdout.write(f"    [+] New finding: {finding_obj.name}")
                else:
                    self.stdout.write(f"    [+] Updated finding: {finding_obj.name}")

            if skipped_without_url:
                self.stderr.write(
                    f"[+] Skipped {skipped_without_url} findings without github_url/Link for keyword {keyword}"
                )

            self.stdout.write(f"[+] Total findings created/updated: {findings_count}")

        except Exception as error:
            self.stderr.write(f"[+] Error running ghleaks scan for keyword {keyword}: {error}")
        finally:
            if report_path and os.path.exists(report_path):
                try:
                    os.remove(report_path)
                except OSError:
                    pass

    def _determine_severity(self, rule_id, description):
        text = f"{rule_id} {description}".lower()
        high_terms = ("secret", "token", "private", "password", "key", "credential")
        medium_terms = ("api", "client", "auth")

        if any(term in text for term in high_terms):
            return "high"
        if any(term in text for term in medium_terms):
            return "medium"
        return "low"
