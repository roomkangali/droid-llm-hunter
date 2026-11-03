import requests
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any

class OllamaClient(BaseLLMClient):
    def __init__(self, model: str, url: str, max_tokens: int = 4096):
        self.model = model
        self.max_tokens = max_tokens
        self.url = f"{url}/api/generate"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to Ollama model: {self.model}...")
        max_retries = 3 # Less retries for local models as errors usually mean model crash/hang
        base_delay = 2 
        import time

        for attempt in range(max_retries):
            try:
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": self.max_tokens},
                }
                # [A] Force valid JSON output for rule-analysis calls. Ollama's native
                # format="json" constrains the model to emit JSON — this is what small
                # local models (deepseek-coder, etc.) need since they otherwise answer in
                # prose and break parsing. NOT set for summarize / risk-ID calls, which
                # legitimately return free text.
                if context.get("expect_json"):
                    payload["format"] = "json"

                response = requests.post(
                    self.url,
                    json=payload,
                    timeout=600, # 10 minutes timeout
                )
                response.raise_for_status()
                result = response.json()["response"]
                log.success("Received analysis from Ollama.")
                return result
            except requests.exceptions.RequestException as e:
                 if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    log.warning(f"Connection error to Ollama: {e}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                 else:
                    log.error(f"Error connecting to Ollama at {self.url} after {max_retries} attempts: {e}")
                    # Return empty string to allow scan to continue (Soft Fail)
                    return ""

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        # This is a basic prompt construction.
        # In a real-world scenario, you would load the system prompt
        # and the specific vulnerability prompt from the config files.
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
