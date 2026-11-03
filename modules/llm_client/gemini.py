from .base import BaseLLMClient
from core import log
from typing import Dict, Any
import requests
import json

class GeminiClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str, max_tokens: int = 4096):
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Gemini model: {self.model}...")
        
        headers = {
            'Content-Type': 'application/json',
            'X-goog-api-key': self.api_key
        }
        
        data = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],
            "generationConfig": {
                "maxOutputTokens": self.max_tokens
            }
        }

        max_retries = 5
        base_delay = 2 # seconds
        import time

        for attempt in range(max_retries):
            try:
                response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)
                
                if response.status_code == 429:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Rate limit hit (429). Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
                
                if response.status_code == 503:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Service Unavailable (503). Retrying in {delay} seconds... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue

                response.raise_for_status()
                result = response.json()
                log.success("Received analysis from Gemini.")
                
                # Check for Gemini's specific error format even in 200 OK responses sometimes
                if "error" in result:
                    log.error(f"Gemini API returned error: {result['error']}")
                    raise requests.exceptions.RequestException(f"Gemini API Error: {result['error']}")

                if not result.get('candidates'):
                     # Sometimes content filtering blocks response
                     log.warning("Gemini returned no candidates (Content Filter?). Returning empty string.")
                     return "{}"

                return result['candidates'][0]['content']['parts'][0]['text']

            except requests.exceptions.RequestException as e:
                # If it's a connection error or timeout, we also retry
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Network error: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    log.error(f"Failed to communicate with Gemini API after {max_retries} attempts: {e}")
                    raise
        
        log.error(f"Gemini API failed after {max_retries} attempts (Rate Limit or Service Unavailable).")
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
