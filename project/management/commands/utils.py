"""Common utilities for management commands."""

import asyncio
import json
import os
import re
import textwrap

from azure.identity import DefaultAzureCredential
from django.conf import settings
from openai import AsyncOpenAI

from agents import (
    Agent,
    ModelSettings,
    Runner,
    set_default_openai_api,
    set_default_openai_client,
    set_tracing_disabled,
    function_tool,
)

def init_ai_client():
    """Initialize and configure the AI client for Azure OpenAI."""
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


class FileAccessHelper:
    """Helper class for file access operations within response directory."""

    def __init__(self, response_dir):
        self.response_dir = response_dir
        self._file_index = None

    def list_files(self):
        """List all files in the response directory."""
        if self._file_index is None:
            self._file_index = []
            for root, dirs, files in os.walk(self.response_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.response_dir)
                    try:
                        size = os.path.getsize(file_path)
                        self._file_index.append({
                            'name': file,
                            'path': rel_path,
                            'size': size,
                        })
                    except Exception:
                        pass
        return self._file_index

    def read_file(self, filename, max_chars=5000):
        """Read a specific file from the response directory."""
        for root, dirs, files in os.walk(self.response_dir):
            for file in files:
                if file == filename:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(max_chars)
                            return {'filename': filename, 'content': content}
                    except Exception as e:
                        return {'filename': filename, 'error': str(e)}
        return {'filename': filename, 'error': 'File not found'}

    def search_files(self, keyword):
        """Search for keyword in filenames and return matching files."""
        keyword_lower = keyword.lower()
        matches = []
        for item in self.list_files():
            if keyword_lower in item['name'].lower():
                matches.append(item)
        return matches

    def grep_file(self, filename, pattern, max_results=5):
        """Search for pattern in a specific file and return matching lines."""
        result = self.read_file(filename, max_chars=50000)
        if 'error' in result:
            return result

        content = result['content']
        lines = content.split('\n')
        matches = []
        pattern_lower = pattern.lower()

        for i, line in enumerate(lines):
            if pattern_lower in line.lower():
                matches.append({
                    'line_number': i + 1,
                    'line': line[:200],  # Limit line length
                })
                if len(matches) >= max_results:
                    break

        return {'filename': filename, 'matches': matches}


async def analyze_with_ai(prompt, model="gpt-4o"):
    """Run AI analysis with the given prompt and return the result."""
    instructions = textwrap.dedent(
        """
        You are a senior penetration tester analyzing web application responses
        for security issues, particularly focusing on exposed secrets, credentials,
        API keys, tokens, passwords, and sensitive data leakage.
        """
    )

    agent = Agent(
        name="Shepherd PenTester",
        instructions=instructions,
        model=model,
        model_settings=ModelSettings(temperature=0.0),
    )

    result = await Runner.run(agent, prompt, max_turns=12)
    return result.final_output


async def analyze_with_file_access(response_dir, asset_value):
    """Analyze files with AI agent using interactive file access tools."""
    helper = FileAccessHelper(response_dir)
    file_list = helper.list_files()

    if not file_list:
        return {"findings": []}

    # Create file access tools using function_tool if available
    # We capture helper in closures so tools can access the file system
    @function_tool
    def list_files() -> str:
        """List all files in the response directory with their sizes."""
        files = helper.list_files()
        if not files:
            return "No files found."
        result = f"Found {len(files)} files:\n"
        for f in files[:100]:  # Limit to 100 files
            result += f"- {f['name']} ({f['size']} bytes)\n"
        return result

    @function_tool
    def read_file(filename: str) -> str:
        """Read a specific file from the response directory. Returns file content or error message."""
        result = helper.read_file(filename, max_chars=5000)
        if 'error' in result:
            return f"Error: {result['error']}"
        return f"File: {filename}\n{result['content']}"

    @function_tool
    def search_files(keyword: str) -> str:
        """Search for files whose names contain the given keyword."""
        matches = helper.search_files(keyword)
        if not matches:
            return f"No files found matching '{keyword}'"
        result = f"Found {len(matches)} files matching '{keyword}':\n"
        for m in matches[:20]:
            result += f"- {m['name']} ({m['size']} bytes)\n"
        return result

    @function_tool
    def grep_file(filename: str, pattern: str) -> str:
        """Search for a pattern in a specific file. Returns matching lines with line numbers."""
        result = helper.grep_file(filename, pattern, max_results=10)
        if 'error' in result:
            return f"Error: {result['error']}"
        if not result.get('matches'):
            return f"No matches found for '{pattern}' in {filename}"
        output = f"Matches in {filename}:\n"
        for match in result['matches']:
            output += f"Line {match['line_number']}: {match['line']}\n"
        return output

    tools = [list_files, read_file, search_files, grep_file]

    # Build initial prompt with file index (just filenames - very small)
    file_index_text = '\n'.join([
        f"- {f['name']} ({f['size']} bytes)" for f in file_list[:50]
    ])

    instructions = textwrap.dedent(
        """
        You are a senior penetration tester analyzing web application responses
        for security issues. You have access to file system tools to explore HTTP responses.

        STRATEGY:
        1. Start by listing files or searching for interesting keywords (password, api_key, token, secret, config, etc.)
        2. Read only files that seem relevant - don't read everything
        3. Use grep to search for specific patterns in files
        4. Focus on finding exposed secrets, credentials, API keys, tokens, passwords, and sensitive data
        """
    )

    task_prompt = textwrap.dedent(f"""
        Analyze HTTP responses in the file system for security leaks.

        FILE INDEX ({len(file_list)} total files available):
        {file_index_text}
        ...

        INSTRUCTIONS:
        Use the available file access tools to explore the files efficiently.
        - Start by searching for keywords like: password, api_key, token, secret, credential, config, admin
        - Read files that might contain sensitive information
        - Use grep to search for specific patterns within files
        - Only read files you're interested in - be selective to save tokens

        After exploring, return ONLY valid JSON:
        {{
          "findings": [
            {{
              "name": "Short title",
              "severity": "Critical | High | Medium | Low | Info",
              "type": "credentials | api_key | token | password | sensitive_data | other",
              "evidence": "Direct quote or reference",
              "reasoning": "Why this is a security issue",
              "recommendation": "Remediation steps",
              "reference": "File name where found"
            }}
          ]
        }}
        Max 10 findings. Be concise.
    """)

    agent = Agent(
        name="Shepherd PenTester",
        instructions=instructions,
        model="gpt-4o",
        model_settings=ModelSettings(temperature=0.0),
        tools=tools
    )

    result = await Runner.run(agent, task_prompt, max_turns=20)
    return extract_json_from_response(result.final_output)


def extract_json_from_response(response_text):
    """Extract JSON from AI response, handling various formats."""
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

    return {"findings": []}
