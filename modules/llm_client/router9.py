import requests
import json
import time
from .base import BaseLLMClient
from core import log
from typing import Dict, Any


class Router9Client(BaseLLMClient):
    """Client for 9Router — a self-hosted, OpenAI-compatible LLM router that fans out
    to many providers/models behind ONE endpoint (e.g. model="gc/gemini-2.5-pro" routes
    through to Gemini). `base_url` is configurable since it's self-hosted (host/port vary
    per install), unlike the other clients in this package which hit a fixed public URL.

    Unlike those other OpenAI-compatible clients, 9Router's /v1/chat/completions endpoint
    was observed to return a Server-Sent Events (SSE) stream even for a plain request with
    no `"stream"` key set — responses arrive as `data: {...}` chunks with `chat.completion.chunk`
    objects and per-token `delta.content` fragments, not a single JSON body.

    However, the `Content-Type: text/event-stream` header is NOT a reliable signal of the
    actual body shape: 9Router has been observed sending `text/event-stream` while the body
    is a single complete (non-chunked) `chat.completion` JSON object glued directly to a
    trailing `data: [DONE]` with no separating newline, e.g.
    `{"id":...,"choices":[{"message":{"content":"..."}}]}data: [DONE]\n\n`. Since that blob
    never starts with `data:`, a naive SSE line-parser silently drops it and returns empty
    content on every single call. This client therefore ignores the header and instead
    sniffs the response body itself to decide whether it's SSE or a plain JSON object.
    """

    def __init__(self, model: str, api_key: str, base_url: str, max_tokens: int = 4096,
                 timeout: int = 300):
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.url = base_url
        self.timeout = timeout

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to 9Router model: {self.model}...")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
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

        max_retries = 3
        base_delay = 2  # seconds

        for attempt in range(max_retries):
            try:
                with requests.post(
                    self.url,
                    headers=headers,
                    json=data,
                    timeout=self.timeout,
                    stream=True,
                ) as response:

                    if response.status_code == 429:
                        log.warning(f"Rate limit hit (429). Retrying... (Attempt {attempt + 1})")
                        time.sleep(base_delay * (2 ** attempt))
                        continue

                    response.raise_for_status()

                    body = response.text
                    content, finish_reason = self._extract_content_and_reason(body)

                if finish_reason == "length":
                    # Deterministic: retrying with the same budget truncates again. Fail
                    # loudly with the fix instead of handing the engine a stub — a
                    # reasoning model spent 8190 of 8192 tokens thinking and returned a
                    # single character, which was then saved as a "PoC".
                    log.error(
                        f"9Router response was TRUNCATED by max_tokens "
                        f"({self.max_tokens}); only {len(content)} char(s) of answer "
                        f"survived. Raise llm.max_tokens — reasoning models spend most "
                        f"of the budget on hidden reasoning before answering."
                    )
                    return ""

                if finish_reason is None and content:
                    # Stream ended without ever reporting why: treat as a dropped
                    # connection and let the retry loop have another go rather than
                    # passing a partial answer off as complete.
                    log.warning(
                        f"9Router stream ended without a finish_reason after "
                        f"{len(content)} char(s); treating as incomplete and retrying."
                    )
                    time.sleep(base_delay * (2 ** attempt))
                    continue

                if content:
                    log.success("Received analysis from 9Router.")
                return content

            except requests.exceptions.RequestException as e:
                log.warning(f"Network error: {e}. Retrying...")
                time.sleep(base_delay * (2 ** attempt))

        log.error(f"9Router API failed after {max_retries} attempts.")
        return ""

    def _extract_content(self, body: str) -> str:
        """Content only. Kept for callers that don't care why generation stopped."""
        return self._extract_content_and_reason(body)[0]

    def _extract_content_and_reason(self, body: str):
        """Sniffs the response body to tell an SSE stream apart from a plain JSON object
        (the `Content-Type` header can't be trusted to say which one it actually is —
        see class docstring), and reports why generation stopped.

        The reason matters: a reasoning model can burn its whole budget on hidden
        `reasoning_content` and return a 1-character answer with
        ``finish_reason: "length"``. Without this the client logs SUCCESS and hands the
        engine a truncated artifact — observed saving "#!/" as a PoC script. Returns
        ``(content, finish_reason)`` where finish_reason is None when the stream ended
        without one (a dropped connection).
        """
        stripped = body.lstrip()
        if stripped.startswith("data:"):
            return self._parse_sse_stream_with_reason(stripped)
        return self._parse_plain_json_with_reason(stripped)

    def _parse_sse_stream(self, body: str) -> str:
        return self._parse_sse_stream_with_reason(body)[0]

    def _parse_sse_stream_with_reason(self, body: str):
        """Accumulates `delta.content` fragments from an OpenAI-style SSE stream
        (`data: {...}` lines, terminated by `data: [DONE]`)."""
        chunks = []
        finish_reason = None
        for raw_line in body.splitlines():
            raw_line = raw_line.strip()
            if not raw_line or not raw_line.startswith("data:"):
                continue
            payload = raw_line[len("data:"):].strip()
            if payload == "[DONE]":
                break
            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if "error" in event:
                log.error(f"9Router stream returned error: {event['error']}")
                continue
            choices = event.get("choices") or []
            if not choices:
                continue
            if choices[0].get("finish_reason"):
                finish_reason = choices[0]["finish_reason"]
            delta = choices[0].get("delta") or {}
            piece = delta.get("content")
            if piece:
                chunks.append(piece)
        return "".join(chunks), finish_reason

    def _parse_plain_json(self, body: str) -> str:
        return self._parse_plain_json_with_reason(body)[0]

    def _parse_plain_json_with_reason(self, body: str):
        """Parses a single `chat.completion` JSON object, tolerating trailing garbage
        (9Router has been observed appending a stray `data: [DONE]` directly after the
        JSON with no separator)."""
        try:
            result, _ = json.JSONDecoder().raw_decode(body)
        except json.JSONDecodeError as e:
            log.error(f"9Router returned unparseable response: {e}")
            return "", None
        if "error" in result:
            log.error(f"9Router API returned error: {result['error']}")
            raise requests.exceptions.RequestException(f"9Router API Error: {result['error']}")
        choices = result.get("choices") or []
        if not choices:
            return "", None
        return choices[0].get("message", {}).get("content", ""), choices[0].get("finish_reason")

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        # .replace() rather than .format(): a rule prompt (or the code snippet spliced
        # into it) can legitimately contain literal braces — a JSON example in the
        # prompt, or decompiled Java/Kotlin — and .format() would read those as
        # placeholders and raise KeyError/IndexError mid-scan. Matches openrouter.py
        # and codex.py.
        formatted_prompt = vuln_prompt.replace("{code_snippet}", code_snippet)
        formatted_prompt = formatted_prompt.replace("{file_path}", context.get("file_path", "N/A"))

        return f"{system_prompt}\n\n{formatted_prompt}"
