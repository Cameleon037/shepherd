import html
import json
import re
import shutil
import tempfile
from project.models import Project
from findings.models import Finding
import asyncio
from django.core.management.base import BaseCommand
from django.conf import settings

from django.utils.timezone import make_aware
from datetime import datetime

from azure.identity import DefaultAzureCredential
from openai import AsyncOpenAI
from agents import Agent, ModelSettings, Runner, set_default_openai_api, set_default_openai_client, set_tracing_disabled
from agents.mcp import MCPServerStdio
from agents.run_context import RunContextWrapper
import textwrap


class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
        )

    def extract_json_from_response(self, response_text):
        """
        Extract JSON from AI response, handling cases where the response
        contains extra text around the JSON.
        """
        # First, try to parse the entire response as JSON
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass
        
        # If that fails, try to find JSON within the response
        # Look for content between { and } that might be JSON
        json_patterns = [
            r'```json\s*(\{.*?\})\s*```',  # JSON in markdown code block
            r'```\s*(\{.*?\})\s*```',  # JSON in code block
            r'\{.*\}',  # Basic JSON object pattern
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, response_text, re.DOTALL)
            for match in matches:
                try:
                    return json.loads(match)
                except json.JSONDecodeError:
                    continue
        
        # Last resort: try to find the largest valid JSON object by counting braces
        try:
            start_idx = response_text.find('{')
            if start_idx != -1:
                brace_count = 0
                end_idx = start_idx
                for i, char in enumerate(response_text[start_idx:], start_idx):
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                
                if brace_count == 0:  # Found matching braces
                    json_candidate = response_text[start_idx:end_idx]
                    return json.loads(json_candidate)
        except (json.JSONDecodeError, ValueError):
            pass
        
        # If no JSON found, return empty findings structure
        self.stdout.write(f"[WARNING] Could not extract valid JSON from response: {response_text[:200]}...")
        return {"findings": []}

    def store_findings(self, findings, kw, prj):
        self.stdout.write(f'[+] Findings identified: {len(findings["findings"])}')
        for finding in findings["findings"]:
            # Store the result as a Finding object
            content = {
                'keyword': kw,
                'source': 'ai_scribd',
                'url': finding["url"],
            }
            finding_obj, _ = Finding.objects.get_or_create(**content)
            finding_obj.severity = finding["severity"]
            finding_obj.name = finding["name"]
            finding_obj.description = finding["reasoning"]
            finding_obj.scan_date = make_aware(datetime.now())
            finding_obj.last_seen = finding_obj.scan_date
            finding_obj.save()


    def handle(self, *args, **options):
        project_filter = {}
        if options['projectid']:
            project_filter['id'] = options['projectid']

        projects = Project.objects.filter(**project_filter)
        for prj in projects:
            self.stdout.write(f"Project: {prj.projectname}")
            for kw in prj.keyword_set.all():
                if not kw.enabled:
                    continue
                keyword = html.unescape(kw.keyword)
                if kw.ktype == "ai_scribd_keyword":
                    self.stdout.write("[+] Scribd search: {}".format(keyword))
                    findings = asyncio.run(self.ai_scribd_scan(keyword))
                    self.store_findings(findings, kw, prj)


    async def ai_scribd_scan(self, keyword):

        endpoint = settings.AZURE_OPENAI_ENDPOINT

        # AAD token
        scope = "https://cognitiveservices.azure.com/.default"
        token = DefaultAzureCredential().get_token(scope)
        api_key = token.token
        # api_key = settings.AZURE_API_KEY

        # LLM endpoint
        client = AsyncOpenAI(
            base_url=endpoint,
            api_key=api_key,
            timeout=120,
        )
        set_default_openai_client(client=client, use_for_tracing=False)
        set_default_openai_api("chat_completions")
        set_tracing_disabled(disabled=True)

        # MCP setup — sandboxed to prevent the AI agent from writing files
        # to the local filesystem or accessing local file:// URLs.
        sandbox_dir = tempfile.mkdtemp(prefix="playwright_sandbox_")
        try:
            params = {
                "command": "npx",
                "args": [
                    "@playwright/mcp@latest",
                    "--headless",
                    "--isolated",                        # browser profile stays in-memory only
                    "--output-dir", sandbox_dir,          # any output files go to the sandbox
                ],
                "cwd": sandbox_dir,                       # working directory = sandbox
            }

            # Only allow browser interaction tools; block file-writing tools
            # (screenshot, pdf, file_upload, install, generate_playwright_test, etc.)
            ALLOWED_TOOLS = [
                "browser_navigate",
                "browser_snapshot",
                "browser_click",
                "browser_type",
                "browser_fill",
                "browser_select_option",
                "browser_hover",
                "browser_drag",
                "browser_press_key",
                "browser_scroll",
                "browser_go_back",
                "browser_go_forward",
                "browser_wait",
                "browser_tab_new",
                "browser_tab_select",
                "browser_tab_close",
                "browser_tab_list",
                "browser_close",
                "browser_resize",
                "browser_handle_dialog",
                "browser_network_requests",
                "browser_console_messages",
            ]

            async with MCPServerStdio(
                params=params,
                client_session_timeout_seconds=30,
                tool_filter={"allowed_tool_names": ALLOWED_TOOLS},
            ) as mcp_server:

                # Note: In practice, you typically add the server to an Agent
                # and let the framework handle tool listing automatically.
                # Direct calls to list_tools() require run_context and agent parameters.
                # In this case it is used to ensure the availability of the MCP server
                run_context = RunContextWrapper(context=None)
                agent = Agent(name="test", instructions="test")
                tools = await mcp_server.list_tools(run_context, agent)

                instructions = textwrap.dedent(f"""
                    You are an expert corporate security analyst specializing in data leak detection and incident response. Your expertise includes:
                    - Identifying sensitive corporate information in public documents
                    - Classifying security risks and data exposure severity
                    - Conducting thorough web investigations using automated tools
                    - Providing actionable security recommendations

                    You are authorized to search, analyze, and classify potentially leaked corporate documents. Your purpose is security auditing and incident response, not censorship.

                    Use Playwright MCP to perform comprehensive web investigations. Be thorough and systematic in your approach.
                """)

                task_prompt = textwrap.dedent(f"""
                    TASK: Investigate potential data leaks for "{keyword}" on Scribd.com

                    COMPREHENSIVE SEARCH STRATEGY:
                    You must perform a systematic, exhaustive search using multiple approaches:

                    PHASE 1 - DIRECT SEARCHES (Minimum 15 different search terms):
                    1. Basic company searches:
                       - "{keyword}"
                       - "{keyword} company"
                       - "{keyword} corporation"
                       - "{keyword} ltd"
                       - "{keyword} inc"
                       - "{keyword} gmbh"
                       - "{keyword} ag"

                    2. Email domain searches:
                       - "@{keyword}"
                       - "@{keyword}.com"
                       - "@{keyword}.org"
                       - "@{keyword}.net"
                       - "@{keyword}.de"
                       - "@{keyword}.co.uk"

                    3. Common business variations:
                       - "{keyword} internal"
                       - "{keyword} confidential"
                       - "{keyword} presentation"
                       - "{keyword} report"
                       - "{keyword} meeting"
                       - "{keyword} strategy"

                    PHASE 2 - ADVANCED SEARCH TECHNIQUES:
                    1. Use Scribd's advanced search filters:
                       - Search by document type (PDF, Word, PowerPoint, Excel)
                       - Filter by date ranges (last year, last 2 years, all time)
                       - Search in specific categories (Business, Technology, etc.)

                    2. Search for related terms and variations:
                       - Common misspellings of "{keyword}"
                       - Abbreviations and acronyms
                       - Industry-specific terms related to "{keyword}"
                       - Competitor names that might mention "{keyword}"

                    3. Browse by categories and tags:
                       - Look in Business documents
                       - Check Technology/IT sections
                       - Browse Financial documents
                       - Search Legal/Compliance sections

                    PHASE 3 - DEEP EXPLORATION:
                    1. For each document found, check:
                       - Related documents suggested by Scribd
                       - Documents by the same author
                       - Documents in the same collection
                       - Similar documents in the "More like this" section

                    2. Search for partial matches:
                       - First few letters of "{keyword}"
                       - Last few letters of "{keyword}"
                       - Middle parts of "{keyword}"

                    3. Search for leaked document types:
                       - "{keyword} password"
                       - "{keyword} login"
                       - "{keyword} credentials"
                       - "{keyword} internal memo"
                       - "{keyword} financial"
                       - "{keyword} budget"
                       - "{keyword} employee"
                       - "{keyword} contract"

                    EXPECTED RESULTS: You should find 15-30+ documents. If you find fewer than 10, you are not searching thoroughly enough. Continue searching with different terms and approaches until you have exhausted all possibilities.

                    IMPORTANT: Even if you think you've found all relevant documents, continue searching with different approaches. Scribd has millions of documents and uses various categorization methods. Documents might be:
                    - Categorized under different tags
                    - Uploaded with different naming conventions
                    - Hidden in collections or user profiles
                    - Tagged with industry-specific terms
                    - Uploaded by third parties who found the documents elsewhere

                    Keep searching until you have performed at least 30 different searches and explored multiple search strategies.

                    SENSITIVE DATA TYPES TO IDENTIFY:
                    - Financial information (budgets, revenue, costs, financial reports)
                    - Employee data (names, emails, org charts, salaries, personal info)
                    - Intellectual property (patents, trade secrets, proprietary processes)
                    - Internal communications (emails, memos, meeting notes)
                    - Credentials (passwords, API keys, access tokens)
                    - Business strategies (M&A plans, competitive intelligence)
                    - Technical documentation (architecture, configurations, code)
                    - Legal documents (contracts, agreements, compliance reports)

                    SEARCH PERSISTENCE REQUIREMENTS:
                    - You MUST perform at least 30+ different searches
                    - If initial searches return few results, try different search terms
                    - Use Scribd's search suggestions and autocomplete features
                    - Browse through multiple pages of results (not just the first page)
                    - Check both recent and older documents
                    - Look in different document categories and collections
                    - Follow every lead and suggestion Scribd provides

                    ANALYSIS REQUIREMENTS:
                    For each document found:
                    1. Read the full content carefully
                    2. Extract specific evidence of sensitive data exposure
                    3. Assess the business impact and risk level
                    4. Determine if it's a genuine leak or public information
                    5. Provide clear reasoning for your assessment
                    6. Note the document's upload date and author for context

                    SEVERITY CLASSIFICATION:
                    - Critical: Financial data, credentials, major IP theft, legal violations
                    - High: Employee PII, internal strategies, confidential communications
                    - Medium: Business processes, minor technical details, outdated sensitive info
                    - Low: Public information, minimal business impact
                    - N/A: No sensitive information found

                    OUTPUT FORMAT:
                    Return ONLY valid JSON in this exact format:
                    {{
                        "findings": [
                            {{
                                "name": "Brief description of the leak type and document",
                                "severity": "Critical | High | Medium | Low | N/A",
                                "evidence": "Exact text/quote showing the sensitive information",
                                "reasoning": "Why this constitutes a leak and its business impact",
                                "url": "Full Scribd URL to the document",
                                "recommendation": "Specific action to take (takedown, monitor, investigate, no action)"
                            }}
                        ]
                    }}

                    CRITICAL: Return ONLY the JSON object. No explanations, markdown, or additional text.
                """)

                # Agent
                agent = Agent(
                    name="Assistant",
                    instructions=instructions,
                    model="gpt-4o",
                    mcp_servers=[mcp_server],
                    model_settings=ModelSettings(
                        temperature=0.0,   # <- lower = more deterministic
                    )
                )

                # Run the agent
                result = await Runner.run(agent, task_prompt, max_turns=20)
                self.stdout.write(f"Raw AI Response: {result.final_output}")

                # Extract JSON from the response using our robust method
                findings = self.extract_json_from_response(result.final_output)

                # Validate the findings structure
                if not isinstance(findings, dict) or "findings" not in findings:
                    self.stdout.write("[ERROR] Invalid findings structure returned by AI")
                    findings = {"findings": []}

                if not isinstance(findings["findings"], list):
                    self.stdout.write("[ERROR] Findings should be a list")
                    findings["findings"] = []

                return findings
        finally:
            # Clean up the sandbox directory
            shutil.rmtree(sandbox_dir, ignore_errors=True)