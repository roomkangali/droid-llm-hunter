import os
import shutil
import subprocess
import tempfile
import time
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any


class ClaudeCliClient(BaseLLMClient):
    """Client for the Claude Code CLI — like CodexClient, this is a local agent binary,
    not an HTTP API, so it is shelled out to (`claude -p ...`) instead of POSTed to.

    Auth is whatever the local `claude` install already uses (its own OAuth login);
    this client never handles credentials itself, which is why there is no `api_key`
    field for it in settings.yaml — run `claude` once interactively to log in and it
    works from here.

    IMPORTANT — this is NOT free usage. Every call bills against the same account/
    subscription as an interactive session (`total_cost_usd` in the CLI's own JSON
    output), and carries a large fixed overhead (~12-18K input tokens) regardless of
    prompt size, before DLH's own prompt content is even counted. Measured against a
    real `sql_injection` rule prompt: ~$0.05-0.08 for a cold call, ~$0.01-0.015 once
    Anthropic's server-side prompt cache is warm (same account, within its ~1h TTL) —
    and 3-11s latency even when warm. That is markedly more expensive and slower than
    router9/haiku for the same call. This client exists for narrow, low-volume use
    (e.g. exploit_provider for PoC generation only), NOT as a bulk/default provider —
    do not point `llm.provider` at this for a multi-hundred-call scan without knowing
    that cost profile.

    Invocation details that matter:
      * `-p` (print/non-interactive) with `--output-format json` so stdout is one JSON
        object (`result`, `is_error`, `total_cost_usd`) instead of a chat transcript.
      * `--tools ""` disables all built-in tools (Bash, Edit, WebFetch, ...) — this
        client is asking for analysis of a code snippet already inlined in the prompt,
        it has no business running commands or touching the filesystem.
      * `--permission-prompts none` so a denied tool-use attempt fails closed instead
        of hanging on a prompt that nothing can answer in a non-interactive subprocess.
      * Each call runs with `cwd` set to a fresh empty temp directory, mirroring
        CodexClient's `--cd`. `claude` auto-discovers CLAUDE.md files upward from its
        working directory; running from DLH's own repo root would silently splice
        DLH's own project instructions into every single analysis prompt. An empty
        temp dir has none to find.
      * Deliberately NOT using `--no-session-persistence`: that flag was measured to
        disable Anthropic's server-side prompt-cache reuse entirely, multiplying cost
        ~6x for no benefit (this client never resumes a session anyway — one process,
        one turn, then it exits).
      * Deliberately NOT using `--bare`: it forces ANTHROPIC_API_KEY-only auth, which
        would bypass the whole point of reusing the existing CLI login.
    """

    def __init__(self, model: str = None, cli_path: str = "claude", max_tokens: int = 4096,
                 timeout: int = 300):
        self.model = model                      # None -> whatever the CLI's own default is (e.g. "sonnet")
        self.cli_path = cli_path or "claude"
        self.max_tokens = max_tokens            # accepted, not enforced: claude CLI exposes no per-call output cap
        self.timeout = timeout

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        label = self.model or "default"
        log.info(f"Sending analysis request to Claude CLI model: {label}...")

        if not shutil.which(self.cli_path):
            log.error(
                f"Claude CLI not found (looked for '{self.cli_path}'). Install it and ensure "
                "it is on PATH, or set llm.claude_cli_path in settings.yaml."
            )
            return ""

        max_retries = 3
        base_delay = 2  # seconds

        for attempt in range(max_retries):
            try:
                content = self._run_claude(prompt)
            except subprocess.TimeoutExpired:
                log.warning(
                    f"Claude CLI timed out after {self.timeout}s "
                    f"(attempt {attempt + 1}/{max_retries})."
                )
                content = None
            except OSError as e:
                log.warning(f"Failed to launch Claude CLI: {e}. Retrying...")
                content = None

            if content:
                log.success("Received analysis from Claude CLI.")
                return content

            if attempt < max_retries - 1:
                time.sleep(base_delay * (2 ** attempt))

        log.error(f"Claude CLI failed after {max_retries} attempts.")
        return ""

    def cache_fingerprint(self) -> str:
        """No settings beyond `model` (already part of the cache key) change the answer
        here, so there is nothing extra to fold in. Present for interface parity with
        CodexClient."""
        return ""

    def _build_command(self) -> list:
        cmd = [
            self.cli_path, "-p",
            "--output-format", "json",
            "--tools", "",
            "--permission-prompts", "none",
        ]
        if self.model:
            cmd += ["--model", self.model]
        return cmd

    def _run_claude(self, prompt: str) -> str:
        """Runs one `claude -p` turn and returns the model's final text answer.

        A fresh temp dir per call serves as the CLI's cwd, so it has no local CLAUDE.md
        to auto-discover and concurrent deep-scan workers never share any on-disk state.
        """
        with tempfile.TemporaryDirectory(prefix="dlh_claude_cli_") as workdir:
            proc = subprocess.run(
                self._build_command(),
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=workdir,
            )

            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "").strip()
                log.warning(
                    f"Claude CLI exited with code {proc.returncode}: {detail[-400:] or '(no output)'}"
                )
                return ""

            stdout = (proc.stdout or "").strip()
            if not stdout:
                log.warning("Claude CLI returned no output.")
                return ""

            try:
                payload = json.loads(stdout)
            except json.JSONDecodeError:
                log.warning(f"Claude CLI returned non-JSON output: {stdout[-400:]}")
                return ""

            if payload.get("is_error"):
                log.warning(f"Claude CLI reported an error: {payload.get('result', '')[:400]}")
                return ""

            return (payload.get("result") or "").strip()

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        # .replace() rather than .format(): decompiled Java/Kotlin is full of braces that
        # would otherwise be read as format placeholders and raise.
        formatted_prompt = vuln_prompt.replace("{code_snippet}", code_snippet)
        formatted_prompt = formatted_prompt.replace("{file_path}", context.get("file_path", "N/A"))

        return f"{system_prompt}\n\n{formatted_prompt}"
