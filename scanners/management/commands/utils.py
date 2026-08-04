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
        """Read a specific file from the response directory.
        
        Note: index.txt is always read in full (no truncation) as it's needed for filename-to-URL mapping.
        """
        for root, dirs, files in os.walk(self.response_dir):
            for file in files:
                if file == filename:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            # Always read index.txt in full - it's critical for URL mapping
                            if filename == 'index.txt':
                                content = f.read()
                            else:
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

    def grep_all_files(self, pattern, max_results_per_file=3, max_files=20):
        """Search for pattern across all files in the response directory (like grep -ir)."""
        pattern_lower = pattern.lower()
        all_matches = []
        files_searched = 0

        for file_info in self.list_files():
            if files_searched >= max_files:
                break
            
            filename = file_info['name']
            result = self.read_file(filename, max_chars=50000)
            
            if 'error' in result:
                continue
            
            content = result['content']
            lines = content.split('\n')
            file_matches = []
            
            for i, line in enumerate(lines):
                if pattern_lower in line.lower():
                    file_matches.append({
                        'line_number': i + 1,
                        'line': line[:200],  # Limit line length
                    })
                    if len(file_matches) >= max_results_per_file:
                        break
            
            if file_matches:
                all_matches.append({
                    'filename': filename,
                    'matches': file_matches
                })
            
            files_searched += 1

        return {'pattern': pattern, 'total_files_with_matches': len(all_matches), 'results': all_matches}


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


async def analyze_with_file_access(response_dir, asset_value, verbose_logger=None):
    """Analyze files with AI agent using interactive file access tools.
    
    Args:
        response_dir: Directory containing HTTP response files
        asset_value: Asset value for context
        verbose_logger: Optional function to log verbose output (e.g., self.stdout.write)
    """
    if verbose_logger:
        verbose_logger(f'[AI] Starting analysis of {len(os.listdir(response_dir)) if os.path.exists(response_dir) else 0} files in {response_dir}')
    
    helper = FileAccessHelper(response_dir)
    file_list = helper.list_files()

    if not file_list:
        if verbose_logger:
            verbose_logger('[AI] No files found in response directory')
        return {"findings": []}
    
    if verbose_logger:
        verbose_logger(f'[AI] Found {len(file_list)} files to analyze')

    # Create file access tools using function_tool
    # We capture helper in closures so tools can access the file system
    if verbose_logger:
        verbose_logger('[AI] Creating interactive file access tools')
    
    @function_tool
    def list_files() -> str:
        """List all files in the response directory with their sizes."""
        if verbose_logger:
            verbose_logger('[AI TOOL] list_files() called')
        files = helper.list_files()
        if not files:
            result = "No files found."
        else:
            result = f"Found {len(files)} files:\n"
            for f in files[:100]:  # Limit to 100 files
                result += f"- {f['name']} ({f['size']} bytes)\n"
        if verbose_logger:
            verbose_logger(f'[AI TOOL] list_files() returned {len(result)} chars')
        return result

    @function_tool
    def read_file(filename: str) -> str:
        """Read a specific file from the response directory. Returns file content or error message.
        
        Note: index.txt is always read in full (no truncation) as it's needed for filename-to-URL mapping.
        Other files are truncated to 5000 characters.
        """
        if verbose_logger:
            verbose_logger(f'[AI TOOL] read_file(filename="{filename}") called')
        # read_file method automatically reads index.txt in full
        result = helper.read_file(filename, max_chars=5000)
        if 'error' in result:
            output = f"Error: {result['error']}"
        else:
            output = f"File: {filename}\n\nContent:\n{result['content']}"
        if verbose_logger:
            if filename == 'index.txt':
                verbose_logger(f'[AI TOOL] read_file() returned {len(output)} chars (full file, no truncation)')
            else:
                verbose_logger(f'[AI TOOL] read_file() returned {len(output)} chars (truncated to 5000)')
        return output

    @function_tool
    def search_files(keyword: str) -> str:
        """Search for files whose names contain the given keyword."""
        if verbose_logger:
            verbose_logger(f'[AI TOOL] search_files(keyword="{keyword}") called')
        matches = helper.search_files(keyword)
        if not matches:
            result = f"No files found matching '{keyword}'"
        else:
            result = f"Found {len(matches)} files matching '{keyword}':\n"
            for m in matches[:20]:
                result += f"- {m['name']} ({m['size']} bytes)\n"
        if verbose_logger:
            verbose_logger(f'[AI TOOL] search_files() found {len(matches)} matches')
        return result

    @function_tool
    def grep_file(filename: str, pattern: str) -> str:
        """Search for a pattern in a specific file. Returns matching lines with line numbers."""
        if verbose_logger:
            verbose_logger(f'[AI TOOL] grep_file(filename="{filename}", pattern="{pattern}") called')
        result = helper.grep_file(filename, pattern, max_results=10)
        if 'error' in result:
            output = f"Error: {result['error']}"
        elif not result.get('matches'):
            output = f"No matches found for '{pattern}' in {filename}"
        else:
            output = f"Matches in {filename}:\n"
            for match in result['matches']:
                output += f"Line {match['line_number']}: {match['line']}\n"
        if verbose_logger:
            match_count = len(result.get('matches', [])) if 'matches' in result else 0
            verbose_logger(f'[AI TOOL] grep_file() found {match_count} matches')
        return output

    @function_tool
    def grep_all_files(pattern: str) -> str:
        """Search for a pattern across all files in the response directory (like grep -ir). Returns matches from multiple files at once."""
        if verbose_logger:
            verbose_logger(f'[AI TOOL] grep_all_files(pattern="{pattern}") called')
        result = helper.grep_all_files(pattern, max_results_per_file=3, max_files=20)
        if not result.get('results'):
            output = f"No matches found for '{pattern}' across all files"
        else:
            output = f"Found '{pattern}' in {result['total_files_with_matches']} file(s):\n\n"
            for file_result in result['results']:
                filename = file_result['filename']
                matches = file_result['matches']
                output += f"File: {filename}\n"
                for match in matches:
                    output += f"  Line {match['line_number']}: {match['line']}\n"
                output += "\n"
        if verbose_logger:
            files_with_matches = result.get('total_files_with_matches', 0)
            verbose_logger(f'[AI TOOL] grep_all_files() found matches in {files_with_matches} files')
        return output

    tools = [list_files, read_file, search_files, grep_file, grep_all_files]
    if verbose_logger:
        verbose_logger(f'[AI] Created {len(tools)} interactive tools')

    # Build initial prompt with file index (just filenames - very small)
    file_index_text = '\n'.join([
        f"- {f['name']} ({f['size']} bytes)" for f in file_list[:50]
    ])

    if verbose_logger:
        verbose_logger(f'[AI] Building prompt with {len(file_list)} files (showing first 50 in index)')
        verbose_logger(f'[AI] File index preview: {file_index_text[:200]}...')

    instructions = textwrap.dedent(
        """
        You are a senior penetration tester analyzing web application responses
        for security issues. You have access to file system tools to explore HTTP responses.

        STRATEGY:
        1. Start by listing files to understand the structure and identify patterns in filenames
        2. Based on the file names and context, intelligently determine what keywords might indicate sensitive data
        3. Search for files using keywords that are relevant to this specific application/context
        4. Read only files that seem relevant - don't read everything
        5. Use grep_all_files to search for patterns across all files at once (more efficient than grep_file for each file)
        6. Use grep_file to search for specific patterns within individual files when needed
        7. Focus on finding exposed secrets, credentials, API keys, tokens, passwords, and sensitive data
        8. Be creative and adaptive - different applications may expose different types of sensitive information

        IMPORTANT EXCLUSIONS:
        - DO NOT report findings for cookies (Set-Cookie headers) - these are session cookies saved by the crawler, not hardcoded secrets
        - DO NOT report findings for CSRF tokens - these are normal security tokens in responses, not exposed secrets
        - DO NOT report findings for standard HTTP headers like Set-Cookie, X-CSRF-Token, etc. unless they contain actual hardcoded credentials
        - Only report actual security leaks: hardcoded API keys, passwords, access tokens, private keys, database credentials, etc.
        """
    )

    task_prompt = textwrap.dedent(f"""
        Analyze HTTP responses in the file system for security leaks.

        FILE INDEX ({len(file_list)} total files available):
        {file_index_text}
        ...

        INSTRUCTIONS:
        Use the available file access tools to explore the files efficiently and intelligently.
        
        EXPLORATION STRATEGY:
        1. CRITICAL FIRST STEP: Read index.txt file to understand the filename-to-URL mapping. This file maps each response filename to its original URL.
        2. List files to understand the structure and identify patterns in filenames
        3. Analyze the file names to determine what keywords might be relevant for this specific application
        4. Based on the context (file names, paths, application type), identify what types of sensitive data might be exposed
        5. Search for files using keywords that make sense for this specific context - don't rely on generic lists
        6. Read files that might contain sensitive information based on your analysis
        7. Use grep_all_files to search for patterns across all files at once - this is more efficient than searching files individually
        8. Use grep_file to search within specific files when you need more detailed results
        9. Be selective - only read files you're interested in to save tokens
        10. Adapt your search strategy based on what you discover - different applications expose different vulnerabilities

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
              "reference": "Original URL where the finding was identified (must be a full URL from index.txt, NOT a filename)"
            }}
          ]
        }}
        
        CRITICAL REQUIREMENTS:
        - You MUST read index.txt first to understand the filename-to-URL mapping
        - The "reference" field MUST contain the original URL (e.g., "https://example.com/path") from index.txt, NOT the filename
        - The "evidence" field should start with the URL where the finding was found, followed by the evidence
        - Example evidence format: "URL: https://example.com/api/config\nFound: API key exposed in response headers"
        - Always use the URL from index.txt when reporting findings - never use filenames in the reference field

        EXCLUSIONS - DO NOT REPORT:
        - Cookies (Set-Cookie headers) - these are session cookies saved by the crawler, not hardcoded secrets
        - CSRF tokens (X-CSRF-Token, csrf_token, etc.) - these are normal security tokens in responses
        - Standard HTTP headers unless they contain actual hardcoded credentials
        - Session IDs, session tokens, or temporary authentication tokens
        - Only report actual security leaks: hardcoded API keys, passwords, access tokens, private keys, database credentials, etc.
        
        Max 10 findings. Be concise.
    """)

    if verbose_logger:
        verbose_logger(f'[AI] Instructions length: {len(instructions)} chars')
        verbose_logger(f'[AI] Task prompt length: {len(task_prompt)} chars')
        verbose_logger('[AI] Creating agent with model: gpt-4o')

    agent = Agent(
        name="Shepherd PenTester",
        instructions=instructions,
        model="gpt-4o",
        model_settings=ModelSettings(temperature=0.0),
        tools=tools
    )

    if verbose_logger:
        verbose_logger('[AI] Starting agent execution (max_turns=30)...')
    
    try:
        result = await Runner.run(agent, task_prompt, max_turns=30)
        
        if verbose_logger:
            verbose_logger(f'[AI] Agent execution completed')
            
            # Log all available attributes of result object for debugging
            result_attrs = [attr for attr in dir(result) if not attr.startswith('_')]
            verbose_logger(f'[AI] Result object attributes: {", ".join(result_attrs)}')
            
            # Check if result has turn information
            if hasattr(result, 'turns') and result.turns:
                verbose_logger(f'[AI] Total turns used: {len(result.turns)}')
                for i, turn in enumerate(result.turns, 1):
                    verbose_logger(f'[AI TURN {i}] Processing turn...')
                    if hasattr(turn, 'messages') and turn.messages:
                        for j, msg in enumerate(turn.messages, 1):
                            if hasattr(msg, 'content') and msg.content:
                                content = str(msg.content)
                                # Truncate for readability
                                display_content = content[:500] + '...' if len(content) > 500 else content
                                verbose_logger(f'[AI TURN {i} MSG {j}] {display_content}')
                    if hasattr(turn, 'agent_response') and turn.agent_response:
                        response = str(turn.agent_response)
                        display_response = response[:500] + '...' if len(response) > 500 else response
                        verbose_logger(f'[AI TURN {i} RESPONSE] {display_response}')
            
            # Log final output with better formatting
            verbose_logger(f'[AI] Final output length: {len(result.final_output)} chars')
            
            # Log full final output (truncated if too long)
            if len(result.final_output) > 2000:
                verbose_logger(f'[AI] Final output (first 2000 chars):')
                for line in result.final_output[:2000].split('\n'):
                    verbose_logger(f'[AI OUTPUT]   {line}')
                verbose_logger(f'[AI] ... (truncated, showing first 2000 of {len(result.final_output)} chars)')
            else:
                verbose_logger(f'[AI] Final output:')
                for line in result.final_output.split('\n'):
                    verbose_logger(f'[AI OUTPUT]   {line}')
        
        findings_data = extract_json_from_response(result.final_output)
        
        if verbose_logger:
            findings_count = len(findings_data.get('findings', []))
            verbose_logger(f'[AI] Extracted {findings_count} findings from response')
            if findings_count > 0:
                for i, finding in enumerate(findings_data.get('findings', [])[:3], 1):
                    verbose_logger(f'[AI] Finding {i}: {finding.get("name", "Unknown")} ({finding.get("severity", "Unknown")})')
        
        return findings_data
    except Exception as e:
        if verbose_logger:
            verbose_logger(f'[AI] ERROR during agent execution: {e}')
            import traceback
            verbose_logger(f'[AI] Traceback: {traceback.format_exc()}')
        raise


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
