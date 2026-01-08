import asyncio
import json
import re
import textwrap
from datetime import datetime

from azure.identity import DefaultAzureCredential
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.timezone import make_aware
from openai import AsyncOpenAI

from agents import (
    Agent,
    ModelSettings,
    Runner,
    set_default_openai_api,
    set_default_openai_client,
    set_tracing_disabled,
)
from project.models import Asset, Project, DNSRecord
from findings.models import Finding, Port, Screenshot


class Command(BaseCommand):
    help = "Run AI-assisted review of monitored domains to surface new findings"

    def add_arguments(self, parser):
        parser.add_argument(
            "--projectid",
            type=int,
            help="Filter by specific project ID",
        )
        parser.add_argument(
            "--uuids",
            type=str,
            help="Comma separated list of Asset UUIDs to process",
            required=False,
        )

    def handle(self, *args, **options):
        assets = self._select_assets(options)
        if not assets:
            self.stdout.write("[INFO] No assets to analyze.")
            return

        self._init_ai_client()

        for asset in assets:
            context = self._build_asset_context(asset)
            if not context["dns_records"] and not context["open_ports"] and not context["screenshots"]:
                self.stdout.write(f"[-] Skipping {asset.value}: no DNS/ports/screenshots context available.")
                continue

            self.stdout.write(f"[+] Analyzing domain: {asset.value}")
            Finding.objects.filter(domain=asset, source="shepherdai").delete()
            findings = asyncio.run(self._analyze_asset(asset.value, context["json_blob"]))
            self._store_findings(asset, findings)

    def _select_assets(self, options):
        uuids_arg = options.get("uuids")
        queryset = Asset.objects.filter(monitor=True, type__in=["domain", "starred_domain"])
        if options.get("projectid"):
            queryset = queryset.filter(related_project_id=options["projectid"])
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            queryset = queryset.filter(uuid__in=uuid_list)
        return list(queryset.order_by("value"))

    def _init_ai_client(self):
        endpoint = settings.AZURE_OPENAI_ENDPOINT
        scope = "https://cognitiveservices.azure.com/.default"
        token = DefaultAzureCredential().get_token(scope)
        api_key = token.token

        client = AsyncOpenAI(
            base_url=endpoint,
            api_key=api_key,
            timeout=120,
        )
        set_default_openai_client(client=client, use_for_tracing=False)
        set_default_openai_api("chat_completions")
        set_tracing_disabled(disabled=True)

    async def _analyze_asset(self, domain_name, context_blob):
        instructions = textwrap.dedent(
            """
            You are a senior penetration tester reviewing reconnaissance data for potential security issues.
            Use all provided context to identify new, actionable findings for the organization.
            Focus on exposed secrets, misconfigurations, sensitive content, vulnerable services, or noteworthy risks.
            """
        )

        task_prompt = textwrap.dedent(
            f"""
            DOMAIN UNDER REVIEW: {domain_name}

            CONTEXT:
            {context_blob}

            TASKS:
            - Review DNS records, open services, screenshots, response bodies, and historic findings.
            - Identify new findings that are NOT already listed in existing findings unless you have better evidence.
            - Highlight secrets, credentials, tokens, admin portals, exposed debug endpoints, or sensitive data leakage.
            - Provide actionable recommendations tailored to the issue.

            OUTPUT FORMAT:
            Return ONLY valid JSON with this structure:
            {{
              "findings": [
                {{
                  "name": "Short title",
                  "severity": "Critical | High | Medium | Low | Info",
                  "type": "http | ssl | dns | application | credentials | misconfiguration | other",
                  "evidence": "Direct quote or reference from the context",
                  "reasoning": "Why this matters",
                  "recommendation": "Concrete remediation steps",
                  "reference": "Optional URL or identifier from the context"
                }}
              ]
            }}
            Ensure the JSON is valid and concise (max 5 findings).
            """
        )

        agent = Agent(
            name="Shepherd PenTester",
            instructions=instructions,
            model="gpt-4o",
            model_settings=ModelSettings(temperature=0.0),
        )

        result = await Runner.run(agent, task_prompt, max_turns=12)
        return self._extract_json_from_response(result.final_output)

    def _build_asset_context(self, asset):
        def serialize_queryset(queryset, fields):
            serialized = []
            for item in queryset.values(*fields):
                for field, value in item.items():
                    if isinstance(value, datetime):
                        item[field] = value.isoformat()
                serialized.append(item)
            return serialized

        dns_records = serialize_queryset(
            DNSRecord.objects.filter(related_asset=asset),
            ["record_type", "record_value", "ttl", "last_checked"],
        )
        open_ports = serialize_queryset(
            Port.objects.filter(domain=asset).order_by("port"),
            ["port", "banner", "product", "cpe", "scan_date"],
        )
        screenshots = []
        for shot in Screenshot.objects.filter(domain=asset).order_by("-date")[:3]:
            screenshots.append(
                {
                    "url": shot.url,
                    "title": shot.title,
                    "status_code": shot.status_code,
                    "webserver": shot.webserver,
                    "response_body": shot.response_body,
                    "captured_at": shot.date.isoformat() if shot.date else None,
                }
            )

        existing_findings = serialize_queryset(
            Finding.objects.filter(domain=asset).order_by("-scan_date")[:10],
            ["name", "severity", "description", "reported", "scan_date"],
        )

        json_context = {
            "domain": asset.value,
            "scope": asset.scope,
            "description": asset.description,
            "dns_records": dns_records,
            "open_ports": open_ports,
            "screenshots": screenshots,
            "existing_findings": existing_findings,
        }
        return {
            "dns_records": dns_records,
            "open_ports": open_ports,
            "screenshots": screenshots,
            "json_blob": json.dumps(json_context, ensure_ascii=False, indent=2),
        }

    def _extract_json_from_response(self, response_text):
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        patterns = [
            r"```json\s*(\{.*?\})\s*```",
            r"```\s*(\{.*?\})\s*```",
            r"\{.*\}",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue

        self.stdout.write("[WARNING] Could not parse AI response as JSON.")
        return {"findings": []}

    def _store_findings(self, asset, findings):
        payload = findings or {}
        results = payload.get("findings", [])
        if not isinstance(results, list):
            self.stdout.write("[WARNING] AI returned invalid findings list.")
            return

        self.stdout.write(f"[+] New findings identified: {len(results)}")
        for finding in results:
            name = finding.get("name")
            if not name:
                continue

            severity_raw = finding.get("severity", "Info") or "Info"
            severity_normalized = severity_raw.lower()
            finding_type = finding.get("type", "other") or "other"
            evidence = finding.get("evidence", "") or ""
            reasoning = finding.get("reasoning", "") or ""
            recommendation = finding.get("recommendation", "") or ""
            reference = finding.get("reference", "") or ""

            description_parts = [
                reasoning or "",
                f"Evidence: {evidence}" if evidence else "",
                f"Recommendation: {recommendation}" if recommendation else "",
            ]
            description_text = "\n\n".join([part for part in description_parts if part])

            finding_obj = Finding.objects.create(
                domain=asset,
                domain_name=asset.value,
                keyword=asset.related_keyword,
                source="shepherdai",
                name=name,
                type=finding_type.lower(),
                severity=severity_normalized,
                description=description_text,
                reference=reference,
                scan_date=make_aware(datetime.now()),
                last_seen=make_aware(datetime.now()),
                reported=False,
            )

            self.stdout.write(f"    - Stored finding: {finding_obj.name} ({severity_raw})")

