import requests
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any
import time

class AnthropicClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str, max_tokens: int = 4096):
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.url = "https://api.anthropic.com/v1/messages"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Anthropic model: {self.model}...")

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        
        data = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        max_retries = 5
        base_delay = 2

        for attempt in range(max_retries):
            try:
                response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)
                
                if response.status_code == 429: # Rate limit
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Rate limit hit (429). Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
                
                if response.status_code == 503 or response.status_code == 529: # Service overloaded
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Service Unavailable ({response.status_code}). Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue

                response.raise_for_status()
                result = response.json()
                
                if "error" in result:
                    type = result['error'].get('type', 'Unknown')
                    message = result['error'].get('message', 'Unknown Error')
                    log.error(f"Anthropic API returned error: {type} - {message}")
                    raise requests.exceptions.RequestException(f"Anthropic API Error: {message}")

                log.success("Received analysis from Anthropic.")
                # Response format: { "content": [ { "text": "..." } ] }
                return result['content'][0]['text']

            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Network error: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    log.error(f"Failed to communicate with Anthropic API after {max_retries} attempts: {e}")
                    # Return empty string to allow scan to continue (Soft Fail)
                    return ""

        log.error(f"Anthropic API failed after {max_retries} attempts.")
        return ""

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        # .replace() rather than .format(): a rule prompt (or the code snippet spliced
        # into it) can legitimately contain literal braces — a JSON example in the
        # prompt, or decompiled Java/Kotlin — and .format() would read those as
        # placeholders and raise KeyError/IndexError mid-scan. Matches router9.py,
        # openrouter.py and codex.py.
        formatted_prompt = vuln_prompt.replace("{code_snippet}", code_snippet)
        formatted_prompt = formatted_prompt.replace("{file_path}", context.get("file_path", "N/A"))

        return f"{system_prompt}\n\n{formatted_prompt}"
