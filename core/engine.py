from .config_loader import Settings
from core import log
from modules.decompiler.apktool_handler import ApktoolHandler
from modules.decompiler.jadx_handler import JadxHandler
from modules.static_analyzer.code_filter import CodeFilter
from modules.llm_client.ollama import OllamaClient
from modules.llm_client.gemini import GeminiClient
from modules.llm_client.groq import GroqClient
from modules.llm_client.openai import OpenAIClient
from modules.llm_client.anthropic import AnthropicClient
from modules.llm_client.openrouter import OpenRouterClient
from modules.llm_client.router9 import Router9Client
from modules.llm_client.codex import CodexClient
from core.call_graph import CallGraphBuilder
from core.manifest_parser import ManifestParser
import os
import yaml
import concurrent.futures
import threading
import tempfile
import stat
import zipfile
import shutil
import ast
import re
import subprocess
import time
from html.parser import HTMLParser
from rich.progress import track
from core.logger import console

# Rules evaluated ONLY against AndroidManifest.xml (in analyze_manifest), never against
# code files in the deep scan. Single source of truth so the two paths can't drift —
# a missing entry here previously let `strandhogg` leak into the code deep-scan and
# false-positive on every risky Java file.
MANIFEST_RULES = ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack", "strandhogg"]

# Rules that have their OWN dedicated analysis pass and must NEVER run in the generic code
# deep-scan (analyze_file) — otherwise they leak and false-positive on .java files.
# Manifest rules run in analyze_manifest; hardcoded_secrets_xml runs in analyze_strings_xml.
DEDICATED_PASS_RULES = set(MANIFEST_RULES) | {"hardcoded_secrets_xml"}

# [#E report-dedup] Rules that detect the same underlying issue share a "family". On the
# same file, findings in one family collapse into a single entry; the rest move under
# 'also_detected_by' (never deleted). Rules not listed are their own singleton family.
VULN_FAMILIES = {
    "webview_xss": "webview", "insecure_webview": "webview",
    "webview_file_access": "webview", "webview_deeplink": "webview",
    "insecure_storage": "storage", "insecure_file_permissions": "storage",
    "exported_components": "ipc", "intent_spoofing": "ipc",
    "deeplink_hijack": "deeplink", "deeplink_logic_bypass": "deeplink",
}
# Broad conceptual rule(s): on a file that already has a specific finding, these are folded
# into it (kept under 'also_detected_by') so they don't flood the report. If a generic rule
# is the ONLY finding on a file, it stays as a standalone finding.
GENERIC_RULES = {"universal_logic_flaw"}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
POC_STATUSES = frozenset({
    "generated", "validation-error", "execution-error", "reproduced",
    "not-reproduced", "Unanalyzed",
})

# [#C] Appended to every RULE prompt (deep-scan + manifest + strings) as the LAST instruction,
# so it overrides any prose-inviting wording inside a rule ("explain...", "say Safe"). Reduces
# parse failures across providers. Brace-free (vuln_prompt is passed through str.format()).
JSON_ONLY_SUFFIX = (
    "\n\n### RESPONSE FORMAT (STRICT)\n"
    "Return ONLY the single JSON object defined in the system prompt. "
    "No markdown, no code fences, no commentary, and no standalone words such as "
    "'Safe', 'VULNERABLE', 'Yes' or 'No' outside the JSON. "
    "Put the explanation in the description field, the exploit walkthrough in attack_scenario, "
    "and the remediation in recommendation."
)

SUMMARY_BATCH_SUFFIX = (
    "\n\n### BATCH OUTPUT CONTRACT\n"
    "The input is a JSON object with an items array. Summarize every item independently. "
    "Return ONLY one JSON object mapping each opaque id to a non-empty summary string. "
    "Every input id must appear exactly once. Do not add, rename, infer, or omit ids."
)

class Engine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._setup_llm_client()  # sets self.llm_client and self.exploit_llm_client
        self.summaries = {}
        self.masvs_mapping = self._load_masvs_mapping()
        
        self.apk_name = "target_app" # Default fallback
        self.vulnerability_findings = []
        # PoC generation/verification has its own lifecycle. Its failures must not
        # downgrade or remove the static vulnerability finding.
        self.poc_results = []
        self.analysis_errors = []  # [FIX #2] Files/rules that failed LLM analysis (NOT clean)
        
        # Load Call Graph Builder if enabled

    def _load_masvs_mapping(self):
        try:
            with open("config/knowledge_base/masvs_mapping.json", "r") as f:
                import json
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not load MASVS mapping: {e}")
            return {}

    def _enrich_result(self, rule_name: str, result_dict: dict) -> dict:
        """Enriches the LLM result with static MASVS knowledge."""
        if rule_name in self.masvs_mapping:
            masvs_info = self.masvs_mapping[rule_name]
            result_dict["masvs_reference"] = {
                "id": masvs_info["masvs_id"],
                "description": masvs_info["description"],
                "link": masvs_info["reference"]
            }
        return result_dict

    def _setup_llm_client(self):
        """Builds `self.llm_client` (scanning/analysis) and `self.exploit_llm_client`
        (PoC generation). The two are the SAME object unless `llm.exploit_provider` or
        `llm.exploit_model` is set AND exploit generation is actually requested — some
        models refuse or silently return empty output for exploit/PoC generation while
        being fine for vulnerability analysis (see Updatev1.3.0.md). Building the
        exploit-specific client is skipped entirely when exploit generation is off, so a
        typo'd `exploit_provider` never breaks a normal scan."""
        if self.settings.analysis.use_cache:
            log.info("Response cache: ENABLED 💾")

        self.llm_client = self._build_llm_client(self.settings.llm.provider)
        self.exploit_llm_client = self.llm_client

        exploit_provider = self.settings.llm.exploit_provider
        exploit_model = self.settings.llm.exploit_model
        if self.settings.analysis.generate_exploit and (exploit_provider or exploit_model):
            effective_provider = exploit_provider or self.settings.llm.provider
            try:
                self.exploit_llm_client = self._build_llm_client(effective_provider, model_override=exploit_model)
                log.info(
                    f"Exploit generation routed to provider '{effective_provider}'"
                    + (f" (model override: {exploit_model})" if exploit_model else "")
                )
            except Exception as e:
                log.warning(
                    f"Failed to set up exploit_provider '{effective_provider}' ({e}); "
                    "falling back to the main provider/model for exploit generation."
                )
                self.exploit_llm_client = self.llm_client

    def _build_llm_client(self, provider: str, model_override: str = None):
        """Builds a cached client for `provider`. `model_override` lets a secondary use
        (exploit generation) pick a different model on that same provider than the one
        used for scanning/analysis; when None, that provider's own default model field
        is used (unchanged behavior)."""
        max_tokens = self.settings.llm.max_tokens  # [#6] Configurable output limit

        if provider == "ollama":
            model = model_override or self.settings.llm.model
            raw_client = OllamaClient(model=model, url=self.settings.llm.ollama_url, max_tokens=max_tokens)
        elif provider == "gemini":
            model = model_override or self.settings.llm.gemini_model
            raw_client = GeminiClient(model=model, api_key=self.settings.llm.gemini_api_key, max_tokens=max_tokens)
        elif provider == "groq":
            model = model_override or self.settings.llm.groq_model
            raw_client = GroqClient(model=model, api_key=self.settings.llm.groq_api_key, max_tokens=max_tokens)
        elif provider == "openai":
            model = model_override or self.settings.llm.openai_model
            raw_client = OpenAIClient(model=model, api_key=self.settings.llm.openai_api_key, max_tokens=max_tokens)
        elif provider == "anthropic":
            model = model_override or self.settings.llm.anthropic_model
            raw_client = AnthropicClient(model=model, api_key=self.settings.llm.anthropic_api_key, max_tokens=max_tokens)
        elif provider == "openrouter":
            model = model_override or self.settings.llm.openrouter_model
            raw_client = OpenRouterClient(model=model, api_key=self.settings.llm.openrouter_api_key, max_tokens=max_tokens)
        elif provider == "router9":
            model = model_override or self.settings.llm.router9_model
            raw_client = Router9Client(
                model=model,
                api_key=self.settings.llm.router9_api_key,
                base_url=self.settings.llm.router9_base_url,
                max_tokens=max_tokens,
                timeout=self.settings.llm.router9_timeout,
            )
        elif provider == "codex":
            # Local CLI agent, not an HTTP API: no api_key, and `model` may legitimately
            # be None (Codex then uses whatever ~/.codex/config.toml selects).
            model = model_override or self.settings.llm.codex_model
            raw_client = CodexClient(
                model=model,
                cli_path=self.settings.llm.codex_cli_path or "codex",
                max_tokens=max_tokens,
                timeout=self.settings.llm.codex_timeout,
                sandbox=self.settings.llm.codex_sandbox or "read-only",
                reasoning_effort=self.settings.llm.codex_reasoning_effort,
            )
            # The client keeps model=None (so Codex picks its own default), but the cache
            # key must not be the empty string — that would collide with any other
            # unset-model provider. Label it distinctly for cache purposes only.
            model = model or "codex:default"
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")

        # [#4] Wrap in a content-addressed cache (resume + dedup). Key includes the model,
        # so mixing providers/models never collides.
        from core.llm_cache import CachedLLMClient
        cache_dir = "output/.dlh_cache"
        return CachedLLMClient(raw_client, cache_dir, model=model, enabled=self.settings.analysis.use_cache)

    def get_status(self, result: dict) -> str:
        """Return a verdict only when ``is_vulnerable`` is an actual JSON boolean.

        Truthiness is unsafe here: ``"false"`` used to become Vulnerable, while a
        missing field, ``null``, or ``0`` became Not Vulnerable.  Invalid verdicts
        are analysis failures and must never be interpreted as a clean result.
        """
        if not isinstance(result, dict):
            return "Error"
        value = result.get("is_vulnerable")
        if value is True:
            return "Vulnerable"
        if value is False:
            return "Not Vulnerable"
        return "Error"

    def _rule_should_run(self, rule_name: str, prompt_data: dict, content: str) -> bool:
        """
        [FIX #1] Per-rule regex gating for the deep-scan phase.

        In non-'llm_only' modes, skip a rule's LLM call when the rule declares one or
        more detection patterns and NONE of them match the file. Rules without any
        pattern (pure-logic rules like universal_logic_flaw) always run. Bad patterns
        fail open (run the LLM) so a broken regex never silently drops a rule.
        """
        if self.settings.analysis.filter_mode == "llm_only":
            return True

        import re
        rule_patterns = []
        if prompt_data.get("detection_pattern"):
            rule_patterns.append(prompt_data["detection_pattern"])
        static_block = prompt_data.get("static_analysis") or {}
        if static_block.get("patterns"):
            rule_patterns.extend(static_block["patterns"])

        if not rule_patterns:
            return True  # No pattern -> logic rule, always run.

        try:
            return any(re.search(p, content, re.IGNORECASE | re.DOTALL) for p in rule_patterns)
        except re.error as e:
            log.warning(f"Invalid detection pattern for rule '{rule_name}' ({e}); running LLM anyway.")
            return True

    def _is_failed_response(self, raw_result: str) -> bool:
        """[FIX #2] True when the LLM client soft-failed (empty response after retries)."""
        return not raw_result or not raw_result.strip()

    def _truncate_for_llm(self, text: str) -> str:
        """
        [#5] Guard against oversized file content blowing the context window / cost.

        Keeps the head (imports, class decl, early logic) and the tail (which holds any
        appended external dependency context), dropping the middle with an explicit marker
        so the LLM knows content was omitted. Controlled by analysis.max_input_chars (0 or
        negative disables truncation).
        """
        limit = self.settings.analysis.max_input_chars
        if not limit or limit <= 0 or len(text) <= limit:
            return text

        head_len = int(limit * 0.7)
        tail_len = limit - head_len
        omitted = len(text) - limit
        log.debug(f"Truncating LLM input: {len(text)} -> {limit} chars ({omitted} omitted).")
        return (
            text[:head_len]
            + f"\n\n... [TRUNCATED {omitted} chars to fit context limit] ...\n\n"
            + text[-tail_len:]
        )

    def _build_error_result(
        self,
        file_path: str,
        rule_name: str,
        vuln_name: str,
        reason: str = "empty",
        raw_response: str = "",
        detail: str = "",
    ) -> dict:
        """
        [FIX #2 / B] Report entry for a rule/file that could NOT be analyzed (not clean).

        reason:
          "empty"       -> LLM returned nothing after retries (soft-fail).
          "unparseable" -> LLM returned non-empty output that was not valid JSON
                           (common with local models that answer in prose instead of JSON).
        """
        if not hasattr(self, "analysis_errors"):
            self.analysis_errors = []
        error_entry = {
            "file": file_path,
            "rule": rule_name,
            "stage": "rule_analysis",
            "status": "Unanalyzed",
            "reason": reason,
        }
        if raw_response:
            error_entry["raw_response"] = raw_response
        if detail:
            error_entry["detail"] = detail
        self.analysis_errors.append(error_entry)
        if reason == "unparseable":
            error_msg = ("LLM returned unparseable output (not valid JSON — likely prose, "
                         "common with small local models). This file/rule was NOT verified — "
                         "treat as unanalyzed, not clean.")
        elif reason == "invalid_verdict":
            error_msg = ("LLM returned JSON with a missing or non-boolean 'is_vulnerable' field. "
                         "This file/rule was NOT verified — treat as unanalyzed, not clean.")
        elif reason == "timeout":
            error_msg = ("LLM analysis timed out. This file/rule was NOT verified — "
                         "treat as unanalyzed, not clean.")
        elif reason == "exception":
            error_msg = ("LLM analysis raised an exception. This file/rule was NOT verified — "
                         "treat as unanalyzed, not clean.")
        else:
            error_msg = ("LLM analysis failed (empty response after retries). "
                         "This file/rule was NOT verified — treat as unanalyzed, not clean.")
        error_result = {
            "file": file_path,
            "rule": rule_name,
            "vulnerability": vuln_name,
            "status": "Error",
            "result": {
                "is_vulnerable": None,
                "status_detail": "UNANALYZED",
                "error": error_msg,
                "description": "Analysis could not be completed for this rule.",
            },
        }
        if raw_response:
            error_result["result"]["raw_response"] = raw_response
        return error_result

    def _record_pipeline_error(
        self,
        file_path: str,
        stage: str,
        reason: str,
        detail: str = "",
        raw_response: str = "",
        status: str = "Unanalyzed",
    ):
        """Record a pre-analysis failure without classifying the candidate as clean."""
        if not hasattr(self, "analysis_errors"):
            self.analysis_errors = []
        entry = {
            "file": file_path,
            "rule": f"__{stage}__",
            "stage": stage,
            "status": status,
            "reason": reason,
        }
        if detail:
            entry["detail"] = detail
        if raw_response:
            entry["raw_response"] = raw_response
        self.analysis_errors.append(entry)

    def _collect_cache_errors(self):
        """Copy non-fatal cache I/O/fingerprint failures into the scan audit trail."""
        seen_clients = set()
        for client in (self.llm_client, self.exploit_llm_client):
            client_id = id(client)
            if client_id in seen_clients or not hasattr(client, "cache_stats"):
                continue
            seen_clients.add(client_id)
            for error in client.cache_stats().get("errors", []):
                operation = error.get("operation", "unknown")
                self._record_pipeline_error(
                    error.get("path") or getattr(self, "apk_name", ""),
                    "cache",
                    operation,
                    error.get("detail", ""),
                    status="Error",
                )

    def _metric_add(self, name: str, amount: int = 1):
        """Update observability counters without participating in scan decisions."""
        metrics = getattr(self, "scan_metrics", None)
        if metrics is None:
            return
        lock = getattr(self, "_metrics_lock", None)
        if lock is None:
            metrics[name] = metrics.get(name, 0) + amount
            return
        with lock:
            metrics[name] = metrics.get(name, 0) + amount

    @staticmethod
    def _metric_timer_start():
        """Best-effort monotonic start time; metrics must never break a scan."""
        try:
            return time.monotonic()
        except Exception as exc:
            log.debug(f"Could not start stage timer: {exc}")
            return None

    def _metric_record_duration(self, name: str, started_at):
        """Store a stage duration without exposing it to scan decisions."""
        if started_at is None:
            return
        try:
            duration = max(0.0, time.monotonic() - started_at)
            metrics = getattr(self, "scan_metrics", None)
            if metrics is None:
                return
            lock = getattr(self, "_metrics_lock", None)
            if lock is None:
                metrics[name] = duration
                return
            with lock:
                metrics[name] = duration
        except Exception as exc:
            log.debug(f"Could not record stage timer '{name}': {exc}")

    def _record_deep_rule_outcome(self, status: str):
        """Account for one started deep-rule LLM check without affecting its verdict."""
        self._metric_add("deep_rule_checks_accounted")
        if status == "Vulnerable":
            self._metric_add("deep_rule_checks_completed")
            self._metric_add("deep_rule_checks_vulnerable")
        elif status == "Not Vulnerable":
            self._metric_add("deep_rule_checks_completed")
            self._metric_add("deep_rule_checks_not_vulnerable")
        else:
            self._metric_add("deep_rule_checks_error")

    def _combined_cache_stats(self) -> dict:
        """Return combined scan/exploit cache counters without mutating the pipeline."""
        hits = 0
        misses = 0
        enabled = False
        seen_clients = set()
        for client in (self.llm_client, self.exploit_llm_client):
            client_id = id(client)
            if client_id in seen_clients or not hasattr(client, "cache_stats"):
                continue
            seen_clients.add(client_id)
            stats = client.cache_stats()
            hits += stats.get("hits", 0)
            misses += stats.get("misses", 0)
            enabled = enabled or bool(stats.get("enabled"))
        return {"hits": hits, "misses": misses, "enabled": enabled}

    def _finalize_scan_metrics(self, results: list):
        """Derive report-only counters after all analysis decisions are complete."""
        if not hasattr(self, "scan_metrics"):
            return
        statuses = {"Vulnerable": 0, "Not Vulnerable": 0, "Error": 0}
        for result in results:
            status = result.get("status")
            statuses[status] = statuses.get(status, 0) + 1
        cache = self._combined_cache_stats()
        self.scan_metrics.update({
            "report_results": len(results),
            "vulnerable_results": statuses.get("Vulnerable", 0),
            "not_vulnerable_results": statuses.get("Not Vulnerable", 0),
            "error_results": statuses.get("Error", 0),
            "analysis_errors": len(self.analysis_errors),
            "cache_hits": cache["hits"],
            "cache_misses": cache["misses"],
            "cache_enabled": cache["enabled"],
        })
        by_stage = {}
        for error in self.analysis_errors:
            stage = error.get("stage", "unknown")
            by_stage[stage] = by_stage.get(stage, 0) + 1
        self.scan_metrics["errors_by_stage"] = by_stage

    def _write_failed_scan_report(self):
        """Persist a fatal early-stage failure so it cannot look like a clean scan."""
        self._collect_cache_errors()
        self._finalize_scan_metrics([])
        report = {
            "scan_status": "Error",
            "app_summary": "",
            "attack_surface_map": None,
            "results": [],
            "poc_results": getattr(self, "poc_results", []),
            "analysis_errors": self.analysis_errors,
            "scan_metrics": getattr(self, "scan_metrics", {}),
        }
        with open(self.final_output_file, "w") as f:
            import json
            json.dump(report, f, indent=2)
        log.error(f"Scan failed. Partial error report saved to {self.final_output_file}")

    def _dedupe_findings(self, results: list) -> list:
        """
        [#E] Collapse overlapping 'Vulnerable' findings on the same file so the report isn't
        noisy. Two mechanisms, both INFORMATION-PRESERVING (merged findings are kept under
        'also_detected_by', never dropped):
          1. Family merge  — findings whose rules share a VULN_FAMILIES family (e.g. the
             WebView trio) on the same file collapse into the highest-severity one.
          2. Generic fold  — a GENERIC_RULES finding (universal_logic_flaw) on a file that
             also has a specific finding is folded into that finding; if it is the only
             finding on the file, it stays standalone.
        Non-'Vulnerable' entries (Not Vulnerable / Error) pass through untouched.
        """
        from collections import defaultdict

        def sev(r):
            return _SEVERITY_ORDER.get(str((r.get("result") or {}).get("severity", "")).lower(), 0)

        def brief(r):
            res = r.get("result") or {}
            return {
                "rule": r.get("rule"),
                "vulnerability": r.get("vulnerability"),
                "severity": res.get("severity"),
                "description": res.get("description"),
            }

        vulnerable = [r for r in results if str(r.get("status", "")).lower() == "vulnerable"]
        passthrough = [r for r in results if str(r.get("status", "")).lower() != "vulnerable"]

        by_file = defaultdict(list)
        for r in vulnerable:
            by_file[r.get("file")].append(r)

        deduped = []
        for _file, group in by_file.items():
            # (1) family merge
            fam_groups = defaultdict(list)
            for r in group:
                rule = r.get("rule") or r.get("vulnerability")
                fam_groups[VULN_FAMILIES.get(rule, f"__self__:{rule}")].append(r)
            merged = []
            for _fam, items in fam_groups.items():
                if len(items) == 1:
                    merged.append(items[0])
                    continue
                primary = max(items, key=sev)
                primary.setdefault("also_detected_by", [])
                primary["also_detected_by"].extend(brief(o) for o in items if o is not primary)
                merged.append(primary)

            # (2) generic fold
            generic = [m for m in merged if m.get("rule") in GENERIC_RULES]
            specific = [m for m in merged if m.get("rule") not in GENERIC_RULES]
            if generic and specific:
                host = max(specific, key=sev)
                host.setdefault("also_detected_by", [])
                host["also_detected_by"].extend(brief(g) for g in generic)
                deduped.extend(specific)
            else:
                deduped.extend(merged)

        return passthrough + deduped

    # Archive formats that contain one or more APKs rather than being APKs themselves.
    BUNDLE_EXTENSIONS = (".xapk", ".apks")

    @staticmethod
    def _rank_bundle_apk(name: str) -> int:
        """Rank an APK inside a bundle; lower values are preferred."""
        name = name.lower()
        if name == "universal.apk":
            return 0
        if name in ("base-master.apk", "base.apk"):
            return 1
        if name.endswith("-master.apk"):
            return 2
        if name.startswith("config.") or ".config." in name or name.startswith("split_config."):
            return 4
        return 3

    def _select_bundle_apk(self, extract_dir: str) -> str:
        """Select the best analyzable APK from an extracted XAPK/APKS bundle."""
        candidates = []
        for root, _, files in os.walk(extract_dir):
            for filename in files:
                if filename.lower().endswith(".apk"):
                    full_path = os.path.join(root, filename)
                    candidates.append((
                        self._rank_bundle_apk(filename),
                        -os.path.getsize(full_path),
                        full_path,
                    ))
        if not candidates:
            return None
        candidates.sort()
        return candidates[0][2]

    @staticmethod
    def _safe_extract_bundle(archive_path: str, extract_dir: str):
        """Extract a bundle without allowing archive members to escape its temp dir."""
        root = os.path.realpath(extract_dir)
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = archive.infolist()
            for member in members:
                normalized_name = member.filename.replace("\\", "/")
                destination = os.path.realpath(os.path.join(root, normalized_name))
                if os.path.commonpath((root, destination)) != root:
                    raise ValueError(f"unsafe archive path: {member.filename}")
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise ValueError(f"archive symlink is not allowed: {member.filename}")
            archive.extractall(root, members)

    @staticmethod
    def _describe_decompile_dir(path: str) -> str:
        """Describe why a decompiled tree cannot safely be treated as analyzed."""
        if not os.path.isdir(path):
            return "the directory does not exist"
        entries = os.listdir(path)
        if not entries:
            return "the directory is empty"
        smali_count = sum(
            sum(1 for filename in files if filename.endswith(".smali"))
            for _, _, files in os.walk(path)
        )
        if smali_count:
            return (
                f"it holds {smali_count} .smali files but no AndroidManifest.xml — "
                "the decompile appears incomplete"
            )
        if "unknown" in entries and len(entries) <= 2:
            return "apktool produced only unknown/, indicating an unreadable input archive"
        return (
            "it contains no AndroidManifest.xml "
            f"(top-level entries: {', '.join(sorted(entries)[:6])})"
        )

    def _publish_decompile(self, staging_dir: str, output_dir: str, apk_path: str) -> bool:
        """Atomically promote a complete staging tree while preserving the old tree on failure."""
        required = ("AndroidManifest.xml", "apktool.yml")
        missing = [name for name in required if not os.path.exists(os.path.join(staging_dir, name))]
        if missing:
            log.error(
                f"Decompilation of '{apk_path}' is incomplete; missing: {', '.join(missing)}. "
                f"{self._describe_decompile_dir(staging_dir)}."
            )
            if os.path.exists(os.path.join(output_dir, "AndroidManifest.xml")):
                log.warning(f"Keeping previous usable decompile in '{output_dir}'.")
            shutil.rmtree(staging_dir, ignore_errors=True)
            return False

        previous_dir = f"{output_dir}.old"
        shutil.rmtree(previous_dir, ignore_errors=True)
        try:
            if os.path.exists(output_dir):
                os.rename(output_dir, previous_dir)
            os.rename(staging_dir, output_dir)
        except OSError as exc:
            log.error(f"Could not publish decompiled output: {exc}")
            if not os.path.exists(output_dir) and os.path.exists(previous_dir):
                try:
                    os.rename(previous_dir, output_dir)
                except OSError as rollback_exc:
                    log.error(f"Could not restore previous decompile: {rollback_exc}")
            return False
        shutil.rmtree(previous_dir, ignore_errors=True)
        return True

    def _find_manifest_path(self, start_path: str) -> str:
        """Traverses up the directory tree to find AndroidManifest.xml."""
        current_dir = os.path.dirname(os.path.abspath(start_path))
        while current_dir != "/" and current_dir != "":
            manifest = os.path.join(current_dir, "AndroidManifest.xml")
            if os.path.exists(manifest):
                return manifest
            parent = os.path.dirname(current_dir)
            if parent == current_dir: break
            current_dir = parent
        return ""

    def _get_class_name(self, file_path: str) -> str:
        """Derives class name from file path for Manifest matching."""
        parts = file_path.replace("\\", "/").split("/")
        filename = parts[-1]
        name, _ = os.path.splitext(filename)
        
        # Try to reconstruct package from path (simple heuristic)
        # Stop at common root markers
        package_parts = [name]
        for part in reversed(parts[:-1]):
            if part in ["smali", "java", "src", "main", "decompiled"]:
                break
            package_parts.insert(0, part)
        
        return ".".join(package_parts)

    def _build_global_context(self) -> str:
        """Summarizes all findings into a global context string."""
        if not self.vulnerability_findings:
            return "No previous findings."
        
        summary = "Summary of Vulnerabilities found in other components:\n"
        for finding in self.vulnerability_findings:
            summary += f"- File: {os.path.basename(finding['file_path'])}\n"
            summary += f"  - Vulnerability: {finding['rule_name']}\n"
            summary += f"  - Description: {finding['vuln_description'][:200]}...\n"
        return summary

    def _generate_chained_exploits(self):
        """Iterates through findings and generates exploits using global context."""
        global_context = self._build_global_context()
        log.info("Generating Chained Exploits with Global Context...")
        
        # PoC generation is the most expensive call in the pipeline (measured 32-250s
        # each) and findings are independent of one another — the shared global context
        # is computed once, above. Running them one at a time made total time the SUM of
        # every finding; they now share the same bounded pool as the deep scan.
        # executor.map preserves input order, so poc_results stays deterministic.
        findings = list(self.vulnerability_findings)
        if not findings:
            return

        def _poc_for(finding):
            self._metric_add("exploit_attempts")
            return self._generate_poc(
                finding["file_path"],
                finding["code_snippet"],
                finding["vuln_description"],
                finding["rule_name"],
                global_context
            )

        # Defensive like the metric helpers: callers that construct an Engine without
        # settings (tests, partial pipelines) must degrade to serial, not crash.
        settings = getattr(self, "settings", None)
        configured = getattr(getattr(settings, "analysis", None), "max_workers", 1) or 1
        workers = max(1, min(configured, len(findings)))
        if workers == 1:
            self.poc_results.extend(_poc_for(f) for f in findings)
            return
        log.info(f"Generating {len(findings)} PoC(s) with {workers} worker(s)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            self.poc_results.extend(pool.map(_poc_for, findings))

    @staticmethod
    def _poc_result(file_path: str, rule_name: str, status: str,
                    artifact_path: str = "", error: dict = None,
                    validation: dict = None) -> dict:
        """Build a PoC audit record without modifying its static finding.

        Verification lifecycle values are `generated`, `validation-error`,
        `execution-error`, `reproduced`, and `not-reproduced`. If generation never
        produced an artifact, `Unanalyzed` is used instead of implying safety.
        """
        if status not in POC_STATUSES:
            raise ValueError(f"Unknown PoC status: {status}")
        result = {
            "file": file_path,
            "rule": rule_name,
            "status": status,
            # Runtime verification is intentionally never automatic. A caller may
            # later record reproduced/not-reproduced/execution-error after an
            # explicitly authorized emulator/device run.
            "runtime_status": "not-run",
        }
        if artifact_path:
            result["artifact_path"] = artifact_path
        if error:
            result["error"] = error
        if validation is not None:
            result["validation"] = validation
        return result

    @staticmethod
    def _syntax_check_poc(poc_content: str, extension: str) -> dict:
        """Parse an artifact without executing it."""
        try:
            if extension == ".sh":
                completed = subprocess.run(
                    ["bash", "-n"], input=poc_content, text=True,
                    capture_output=True, timeout=10, check=False,
                )
                if completed.returncode:
                    return {"name": "syntax", "status": "failed",
                            "detail": (completed.stderr or "bash -n failed").strip()}
                return {"name": "syntax", "status": "passed", "detail": "bash -n"}
            if extension == ".py":
                ast.parse(poc_content)
                return {"name": "syntax", "status": "passed", "detail": "ast.parse"}
            if extension == ".js":
                node = shutil.which("node")
                if not node:
                    return {"name": "syntax", "status": "warning",
                            "detail": "node unavailable; JavaScript syntax not verified"}
                completed = subprocess.run(
                    [node, "--check", "-"], input=poc_content, text=True,
                    capture_output=True, timeout=10, check=False,
                )
                if completed.returncode:
                    return {"name": "syntax", "status": "failed",
                            "detail": (completed.stderr or "node --check failed").strip()}
                return {"name": "syntax", "status": "passed", "detail": "node --check"}
            if extension == ".html":
                parser = HTMLParser()
                parser.feed(poc_content)
                parser.close()
                return {"name": "syntax", "status": "passed", "detail": "HTMLParser"}
            return {"name": "syntax", "status": "failed",
                    "detail": f"unsupported runnable artifact type: {extension}"}
        except (SyntaxError, subprocess.TimeoutExpired) as exc:
            return {"name": "syntax", "status": "failed", "detail": str(exc)}
        except Exception as exc:
            return {"name": "syntax", "status": "warning",
                    "detail": f"syntax validator unavailable: {exc}"}

    @staticmethod
    def _target_extra_types(code_snippet: str) -> dict:
        """Extract literal Android extra keys and their expected API types."""
        api_types = {
            "String": "string", "CharSequence": "string", "Parcelable": "parcelable",
            "Serializable": "serializable", "Int": "int", "Integer": "int",
            "Boolean": "boolean", "Long": "long", "Float": "float", "Double": "float",
            "Byte": "int", "Short": "int", "StringArray": "string-array",
            "IntArray": "int-array", "IntegerArrayList": "int-array",
            "LongArray": "long-array", "FloatArray": "float-array",
        }
        found = {}
        for api_name, key in re.findall(
            r"get([A-Za-z]+)Extra\s*\(\s*[\"']([^\"']+)[\"']", code_snippet
        ):
            if api_name in api_types:
                found[key] = api_types[api_name]
        for api_name, key in re.findall(
            r"\.get([A-Za-z]+)\s*\(\s*[\"']([^\"']+)[\"']", code_snippet
        ):
            if api_name in api_types:
                found.setdefault(key, api_types[api_name])
        return found

    @staticmethod
    def _framework_extra_types(code_snippet: str) -> dict:
        """Return framework-owned extras only when inheritance proves the contract.

        PreferenceActivity consumes these keys inside Android framework code, so they
        normally do not appear in the application's decompiled class. They must not be
        globally allowlisted: the same keys remain invalid for unrelated components.
        """
        is_preference_activity = bool(
            re.search(
                r"\bextends\s+(?:android\.preference\.)?PreferenceActivity\b",
                code_snippet,
            )
            or re.search(
                r"(?m)^\s*\.super\s+Landroid/preference/PreferenceActivity;",
                code_snippet,
            )
        )
        if not is_preference_activity:
            return {}
        return {
            ":android:show_fragment": "string",
            ":android:no_headers": "boolean",
        }

    @staticmethod
    def _preference_activity_allows_fragment(code_snippet: str) -> bool:
        """Recognize an unconditional Java or Smali isValidFragment true verdict."""
        java_method = re.search(
            r"\bisValidFragment\s*\([^)]*\)\s*\{(?P<body>.*?)\}",
            code_snippet,
            re.DOTALL,
        )
        if java_method and re.search(r"\breturn\s+true\s*;", java_method.group("body")):
            return True

        smali_method = re.search(
            r"(?ms)^\s*\.method[^\n]*\bisValidFragment\([^\n]*\)Z\s*"
            r"(?P<body>.*?)^\s*\.end method",
            code_snippet,
        )
        if smali_method:
            body = smali_method.group("body")
            true_registers = set(re.findall(
                r"\bconst(?:/4|/16)?\s+([vp]\d+),\s+0x1\b", body
            ))
            return any(re.search(rf"\breturn\s+{re.escape(register)}\b", body)
                       for register in true_registers)
        return False

    @staticmethod
    def _frida_string_constants(poc_content: str) -> dict:
        """Map simple string constants declared in a Frida script.

        Well-written PoCs hoist keys into constants (``var EXTRA_KEY = "forward_intent"``)
        instead of repeating literals. Matching only inline literals made those calls
        invisible to validation and rejected correct artifacts.
        """
        return dict(re.findall(
            r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*['\"]([^'\"]*)['\"]\s*;",
            poc_content,
        ))

    @staticmethod
    def _frida_resolve_string(raw: str, const_strings: dict) -> str:
        """Resolve a quoted literal or a known string constant to its value."""
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] in "'\"" and raw[-1] == raw[0]:
            return raw[1:-1]
        return const_strings.get(raw, raw)

    @staticmethod
    def _frida_put_extra_calls(poc_content: str) -> list:
        """Return literal Frida ``putExtra`` calls with receiver and value flow.

        Keeping the receiver is security-significant for Intent Redirection: an
        extra placed on the outer Intent is part of the vulnerable component's
        input contract, while an extra placed on the attacker-controlled nested
        Intent belongs to the forwarded payload. The previous key-only regex
        erased that distinction and rejected valid observation markers.
        """
        const_strings = Engine._frida_string_constants(poc_content)

        def _resolve_key(raw: str) -> str:
            return Engine._frida_resolve_string(raw, const_strings)

        # A key is either a quoted literal or an identifier resolved above.
        key_pattern = r"(?:['\"][^'\"]+['\"]|[A-Za-z_$][\w$]*)"
        calls = []
        overload_calls = re.compile(
            r"(?P<method_receiver>\b[A-Za-z_$][\w$]*)\.putExtra\.overload\([^;]*?\)"
            r"\s*\.call\(\s*(?P<receiver>[A-Za-z_$][\w$]*)\s*,\s*"
            rf"(?P<key>{key_pattern})\s*,\s*(?P<value>.*?)\)\s*;",
            re.DOTALL,
        )
        direct_calls = re.compile(
            r"(?P<receiver>\b[A-Za-z_$][\w$]*)\.putExtra\s*\(\s*"
            rf"(?P<key>{key_pattern})\s*,\s*(?P<value>.*?)\)\s*;",
            re.DOTALL,
        )
        for pattern in (overload_calls, direct_calls):
            for match in pattern.finditer(poc_content):
                calls.append({
                    "offset": match.start(),
                    "receiver": match.group("receiver"),
                    "key": _resolve_key(match.group("key")),
                    "value": match.group("value").strip(),
                })
        return sorted(calls, key=lambda call: call["offset"])

    @staticmethod
    def _frida_intent_instances(poc_content: str) -> set:
        """Find Frida variables proven to be constructed Android Intent objects."""
        factories = set(re.findall(
            r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"
            r"Java\.use\(\s*['\"]android\.content\.Intent['\"]\s*\)",
            poc_content,
        ))
        instances = set()
        for factory in factories:
            instances.update(re.findall(
                rf"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                rf"{re.escape(factory)}\.\$new\s*\(",
                poc_content,
            ))
        return instances

    @classmethod
    def _frida_nested_intent_receivers(cls, poc_content: str, target_types: dict,
                                       put_extra_calls: list) -> set:
        """Find Intent instances passed as a target's literal Parcelable extra."""
        intent_instances = cls._frida_intent_instances(poc_content)
        nested = set()
        for call in put_extra_calls:
            if target_types.get(call["key"]) != "parcelable":
                continue
            for instance in intent_instances:
                if re.search(rf"\b{re.escape(instance)}\b", call["value"]):
                    nested.add(instance)
        return nested

    @classmethod
    def _validate_poc_artifact(cls, poc_content: str, extension: str,
                               rule_name: str, file_path: str,
                               code_snippet: str, manifest_context: str,
                               global_context: str = "") -> dict:
        """Conservatively validate a generated artifact without running it.

        A check fails only for a proven contradiction (syntax error, invented literal
        target-contract IPC identifier, known extra type mismatch, or crash claimed as Intent
        Redirection success). Ambiguous/dynamic values remain warnings so validation
        cannot become a discovery gate.
        """
        checks = [cls._syntax_check_poc(poc_content, extension)]
        evidence = "\n".join((file_path, code_snippet, manifest_context, global_context))

        # Parse IPC flags only from actual `am` commands. Looking for `-a`/`-n`
        # across an entire shell script would misread ordinary grep/test/curl flags.
        normalized_poc = re.sub(r"\\\s*\n\s*", " ", poc_content)
        ipc_commands = "\n".join(
            line for line in normalized_poc.splitlines()
            if re.search(r"\bam\s+(?:start|broadcast|startservice|start-foreground-service)\b", line)
        )

        # Literal components/actions can be checked against the exact analyzed
        # source/manifest. Shell variables and computed values remain warnings.
        components = re.findall(r"(?:^|\s)-n\s+['\"]?([^\s'\"]+)", ipc_commands)
        for component in components:
            if "$" in component or "${" in component:
                checks.append({"name": "component_provenance", "status": "warning",
                               "detail": f"dynamic component not statically verified: {component}"})
                continue
            class_part = component.rsplit("/", 1)[-1].lstrip(".")
            if class_part and class_part in evidence:
                checks.append({"name": "component_provenance", "status": "passed",
                               "detail": component})
            else:
                checks.append({"name": "component_provenance", "status": "failed",
                               "detail": f"component not found in analyzed code/manifest: {component}"})

        frida_components = re.findall(
            r"\.setClassName\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            poc_content,
        )
        frida_components += re.findall(
            r"ComponentName\.\$new\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            poc_content,
        )
        for package_name, class_name in frida_components:
            component = f"{package_name}/{class_name}"
            simple_name = class_name.rsplit(".", 1)[-1]
            if simple_name in evidence and package_name in evidence:
                checks.append({"name": "component_provenance", "status": "passed",
                               "detail": component})
            else:
                checks.append({"name": "component_provenance", "status": "failed",
                               "detail": f"component not found in analyzed context: {component}"})

        actions = re.findall(r"(?:^|\s)-a\s+['\"]?([^\s'\"]+)", ipc_commands)
        for action in actions:
            if "$" in action:
                checks.append({"name": "action_provenance", "status": "warning",
                               "detail": f"dynamic action not statically verified: {action}"})
            elif action in evidence:
                checks.append({"name": "action_provenance", "status": "passed", "detail": action})
            else:
                checks.append({"name": "action_provenance", "status": "failed",
                               "detail": f"action not found in analyzed code/manifest: {action}"})

        flag_types = {
            "--es": "string", "--esn": "string", "--ei": "int", "--ez": "boolean",
            "--el": "long", "--ef": "float", "--eu": "uri", "--ecn": "component",
            "--esa": "string-array", "--eia": "int-array", "--ela": "long-array",
            "--efa": "float-array",
        }
        target_types = cls._target_extra_types(code_snippet)
        framework_extra_types = cls._framework_extra_types(code_snippet)
        for key, expected_type in framework_extra_types.items():
            target_types.setdefault(key, expected_type)
        extras = re.findall(
            r"(?:^|\s)(--esn|--es|--ei|--ez|--el|--ef|--eu|--ecn|--esa|--eia|--ela|--efa)"
            r"\s+['\"]?([^\s'\"]+)", ipc_commands
        )
        for flag, key in extras:
            if "$" in key:
                checks.append({"name": "extra_provenance", "status": "warning",
                               "detail": f"dynamic extra key not statically verified: {key}"})
                continue
            expected = target_types.get(key)
            if expected is None:
                if key in evidence:
                    checks.append({"name": "extra_provenance", "status": "warning",
                                   "detail": f"extra key found but target type unresolved: {key}"})
                else:
                    checks.append({"name": "extra_provenance", "status": "failed",
                                   "detail": f"extra key not found in analyzed code/manifest: {key}"})
                continue
            if key in framework_extra_types:
                checks.append({
                    "name": "extra_provenance",
                    "status": "passed",
                    "detail": f"{key}: PreferenceActivity framework contract",
                })
            actual = flag_types[flag]
            type_matches = actual == expected or (
                expected == "parcelable" and actual in {"uri", "component"}
            )
            checks.append({
                "name": "extra_type",
                "status": "passed" if type_matches else "failed",
                "detail": (f"{key}: {actual}" if type_matches else
                           f"{key}: PoC sends {actual}, target reads {expected}"),
            })

        frida_extra_calls = cls._frida_put_extra_calls(poc_content)
        frida_extra_keys = [call["key"] for call in frida_extra_calls]
        nested_intent_receivers = cls._frida_nested_intent_receivers(
            poc_content, target_types, frida_extra_calls
        )

        # An action set on the NESTED Intent is the attacker-chosen payload — the whole
        # point of Intent Redirection is that the victim forwards an Intent it never
        # declared. Requiring it to appear in the manifest inverts the threat model and
        # rejects correct PoCs (observed failing a valid nested VIEW payload). Only the
        # outer, entry-point action has to be provable from the analyzed context.
        for _match in re.finditer(
            r"\b([A-Za-z_$][\w$]*)\.setAction\s*\(\s*['\"]([^'\"]+)['\"]", poc_content
        ):
            _receiver, action = _match.group(1), _match.group(2)
            if _receiver in nested_intent_receivers:
                checks.append({
                    "name": "action_provenance",
                    "status": "warning",
                    "detail": f"attacker-controlled nested payload action: {action}",
                })
            else:
                checks.append({
                    "name": "action_provenance",
                    "status": "passed" if action in evidence else "failed",
                    "detail": (action if action in evidence else
                               f"action not found in analyzed context: {action}"),
                })
        # An observation marker is one the script writes AND reads back to prove the
        # redirect happened. Keys are routinely hoisted into constants and probed with
        # hasExtra() as well as get*Extra(), so resolve constants and accept both —
        # otherwise a correct marker reads as an unknown extra and fails validation.
        _poc_constants = Engine._frida_string_constants(poc_content)
        frida_observation_keys = {
            Engine._frida_resolve_string(raw, _poc_constants)
            for raw in re.findall(
                r"\.(?:get[A-Za-z]*Extra|hasExtra)\s*\(\s*"
                r"(['\"][^'\"]+['\"]|[A-Za-z_$][\w$]*)",
                poc_content,
            )
        }
        for call in frida_extra_calls:
            key = call["key"]
            if key in framework_extra_types:
                checks.append({
                    "name": "extra_provenance", "status": "passed",
                    "detail": f"{key}: PreferenceActivity framework contract",
                })
            elif key in target_types or key in evidence:
                checks.append({"name": "extra_provenance", "status": "passed", "detail": key})
            elif (
                rule_name == "intent_redirection"
                and call["receiver"] in nested_intent_receivers
                and key in frida_observation_keys
            ):
                checks.append({
                    "name": "extra_provenance", "status": "warning",
                    "detail": (
                        f"nested Intent observation marker is local to the Frida "
                        f"verification flow: {key}"
                    ),
                })
            else:
                checks.append({"name": "extra_provenance", "status": "failed",
                               "detail": f"extra key not found in analyzed context: {key}"})

        supplied_extra_keys = {key for _, key in extras} | set(frida_extra_keys)
        if ":android:show_fragment" in supplied_extra_keys and framework_extra_types:
            if cls._preference_activity_allows_fragment(code_snippet):
                checks.append({
                    "name": "fragment_policy", "status": "passed",
                    "detail": "isValidFragment unconditionally returns true",
                })
            else:
                checks.append({
                    "name": "fragment_policy", "status": "warning",
                    "detail": "PreferenceActivity contract is present but the requested fragment allow decision is not statically proven",
                })

            exported_match = re.search(
                r"(?im)^\s*Exported:\s*(true|false|none)\s*$", manifest_context
            )
            if exported_match and exported_match.group(1).lower() == "true":
                checks.append({
                    "name": "component_reachability", "status": "passed",
                    "detail": "manifest marks PreferenceActivity component exported",
                })
            elif exported_match and exported_match.group(1).lower() == "false":
                checks.append({
                    "name": "component_reachability", "status": "failed",
                    "detail": "manifest marks PreferenceActivity component non-exported",
                })
            else:
                checks.append({
                    "name": "component_reachability", "status": "warning",
                    "detail": "exported reachability is not proven by manifest context",
                })

        if rule_name == "intent_redirection":
            parcelable_keys = {
                key for key, expected_type in target_types.items()
                if expected_type == "parcelable"
            }
            for key in parcelable_keys:
                if key not in frida_extra_keys and not any(extra_key == key for _, extra_key in extras):
                    checks.append({"name": "intent_payload", "status": "failed",
                                   "detail": f"nested Parcelable extra is never sent: {key}"})
                elif key in frida_extra_keys:
                    checks.append({"name": "intent_payload", "status": "passed",
                                   "detail": f"nested extra constructed with putExtra: {key}"})
            if "startActivity" not in poc_content:
                checks.append({"name": "intent_trigger", "status": "failed",
                               "detail": "artifact never invokes startActivity"})
            else:
                checks.append({"name": "intent_trigger", "status": "passed",
                               "detail": "startActivity invocation present"})

        pass_lines = [line for line in poc_content.splitlines()
                      if re.search(r"\b(pass|success|vulnerable)\b", line, re.IGNORECASE)]
        # A crash is not proof of Intent Redirection, so a script claiming it is must be
        # rejected. But a correct script says the OPPOSITE — "success = activity launched,
        # NOT a ClassCastException" — and a bare keyword search cannot tell the two apart,
        # failing well-formed PoCs for stating the right criterion. Only count a crash
        # mention that is not negated.
        _CRASH_TOKENS = r"classcastexception|securityexception|fatal exception|type[- ]confusion crash|caused .*crash"
        _NEGATORS = r"\b(not|no|never|without|rather than|instead of|avoid(?:s|ed)?|absent|n't)\b|!=|≠"

        def _claims_crash_as_proof(line: str) -> bool:
            for match in re.finditer(_CRASH_TOKENS, line, re.IGNORECASE):
                preceding = line[max(0, match.start() - 60):match.start()]
                if not re.search(_NEGATORS, preceding, re.IGNORECASE):
                    return True
            return False

        crash_claim = any(_claims_crash_as_proof(line) for line in pass_lines)
        if rule_name == "intent_redirection" and crash_claim:
            checks.append({"name": "success_indicator", "status": "failed",
                           "detail": "crash is not proof of Intent Redirection"})
        elif pass_lines:
            checks.append({"name": "success_indicator", "status": "warning",
                           "detail": "runtime success condition requires authorized manual verification"})
        else:
            checks.append({"name": "success_indicator", "status": "warning",
                           "detail": "no explicit success indicator found"})

        failed = [check for check in checks if check["status"] == "failed"]
        return {
            "status": "invalid" if failed else "valid",
            "checks": checks,
            "execution": "not-run",
        }

    def _is_relevant_file(self, file_path: str, package_name: str) -> bool:
        """
        Determines if a file is relevant for analysis based on package scope and blocklist.
        """
        # Blocklist (Libraries to ignore)
        blocklist = [
            "android/", "androidx/", "com/google/", "kotlin/", 
            "okhttp3/", "retrofit2/", "io/reactivex/", "dagger/",
            "b/b/p/", "b/j/a/" # Obfuscated common libs often seen
        ]
        
        # Normalize path
        normalized_path = file_path.replace("\\", "/")
        
        # [FIX] Logic Reordered: Check Whitelist (Package Name) FIRST
        # This prevents apps like 'com.google.myapp' from being blocked by 'com/google/' in blocklist.
        
        # 1. Check Whitelist (Package Name)
        if package_name and "." in package_name:
            package_path = package_name.replace(".", "/")
            if package_path in normalized_path:
                return True
        
        # [V1.1.7 Library Hunter]
        if self.settings.analysis.scan_libraries:
            # If Library Hunter is active, we WANT to see files in the blocklist.
            # We specifically look FOR them.
            # However, we still might want to filter out 'standard java/kotlin' runtime stuff if it's too noisy,
            # but for now, let's just bypass the blocklist check if this mode is on.
            pass 
        else:
            # Standard Mode: Block libraries
            for blocked in blocklist:
                if blocked in normalized_path:
                    # Double Check: Is it actually the app's package?
                    # Sometimes apps use package names that look like libraries? (Rare)
                    return False
            
        # If no package name extracted and not blocked, allow it.
        return True

    def _detect_poc_extension(self, poc_content: str) -> str:
        """Picks the file extension for a generated PoC/verification script.

        The FIRST LINE is authoritative when it matches what `exploit_prompt.txt`
        instructs the model to emit there (a shebang for Bash/Python; an opening
        token for Frida JS/HTML) — checked BEFORE any whole-content substring scan.

        Why: a Bash script may legitimately EMBED another language, e.g. a
        `python3 - << 'EOF' ... EOF` heredoc, because Bash can't easily do things
        like background logcat monitoring on its own. That embedded block contains
        "import "/"def " just like standalone Python would. Scanning the WHOLE
        content for those substrings (the old approach) misclassified such a script
        as ".py" even though it starts with `#!/bin/bash` and is a single, valid,
        directly-executable Bash script — the heredoc is an implementation detail,
        not a second top-level script. The first line is what actually determines
        how the file executes (the OS reads the shebang), so it must win.
        """
        first_line = poc_content.split("\n", 1)[0].strip()

        if first_line.startswith("#!"):
            if "python" in first_line:
                return ".py"
            if "bash" in first_line or first_line.endswith("sh"):
                return ".sh"
        elif first_line.startswith("Java.perform(") or first_line.startswith("setTimeout("):
            return ".js"
        elif first_line.lower().startswith(("<!doctype", "<html")):
            return ".html"

        # No (recognized) first-line signal -> fall back to content sniffing, for the
        # rare case the model doesn't follow the "start with X" instruction.
        if "Java.perform(" in poc_content or "Java.use(" in poc_content or "console.log(" in poc_content:
            return ".js"
        if "<html" in poc_content.lower() or "<script" in poc_content.lower() or "<!doctype" in poc_content.lower():
            return ".html"
        if "import " in poc_content or "def " in poc_content:
            return ".py"
        if "#!/bin/bash" in poc_content or "#!/bin/sh" in poc_content or "adb shell" in poc_content:
            return ".sh"
        return ".txt"

    def _generate_poc(self, file_path: str, code_snippet: str, vuln_description: str, rule_name: str, global_context: str = ""):
        """Generate a PoC artifact and return status independent of the finding."""
        try:
            # [NEW] Manifest Context Injection
            manifest_context = "Manifest not found or Context Injection disabled."
            if self.settings.analysis.use_cross_reference_context: # Reuse context flag or always on? User asked for accuracy.
                manifest_path = self._find_manifest_path(file_path)
                if manifest_path:
                    parser = ManifestParser(manifest_path)
                    class_name = self._get_class_name(file_path)
                    details = parser.get_component_details(class_name)
                    if details and details.get("context_str"):
                        manifest_context = details["context_str"]
                        log.info(f"Injecting Manifest Context for {class_name}")

            # [NEW] Hardcoded Secrets "Auto-Fill"
            # We use a temporary CodeFilter instance to reuse its regex logic, or the main one if available.
            # Since CodeFilter need decompiled_dir, we can pass a dummy one if we just use extract_secrets(content).
            detected_secrets_str = "None detected."
            try:
                # Assuming CodeFilter is imported. We can use a lightweight instance or static method if refactored.
                # But extract_secrets is an instance method.
                # Let's instantiate it with a dummy path since we only process the snippet string here.
                temp_filter = CodeFilter(decompiled_dir="/tmp", mode="java") 
                secrets = temp_filter.extract_secrets(code_snippet)
                if secrets:
                    detected_secrets_str = ""
                    for s in secrets:
                        detected_secrets_str += f"- {s['type']}: \"{s['value']}\"\n"
                    log.info(f"Injecting {len(secrets)} detected secrets into prompt.")
            except Exception as e:
                log.warning(f"Secret extraction failed: {e}")

            # Rule findings carry YAML keys, not display names. Missing evidence only
            # makes the PoC unanalyzed; the confirmed static finding remains intact.
            if rule_name in {"hardcoded_secrets", "hardcoded_secrets_xml"} and detected_secrets_str == "None detected.":
                log.warning(
                    f"Skipping PoC generation for {os.path.basename(file_path)}: "
                    f"rule '{rule_name}' has no secret value extracted for a concrete payload."
                )
                self._record_pipeline_error(
                    file_path,
                    "exploit_generation",
                    "missing_secret_evidence",
                )
                self._metric_add("exploit_errors")
                return self._poc_result(
                    file_path, rule_name, "Unanalyzed",
                    error={"stage": "generation", "reason": "missing_secret_evidence"},
                )

            with open("config/prompts/exploit_prompt.txt", "r") as f:
                prompt_template = f.read()
            
            prompt = prompt_template.replace("{vulnerability_description}", vuln_description)
            prompt = prompt.replace("{rule_name}", rule_name)
            prompt = prompt.replace("{file_path}", file_path)
            prompt = prompt.replace("{manifest_context}", manifest_context) # Inject Manifest
            prompt = prompt.replace("{detected_secrets}", detected_secrets_str) # Inject Secrets
            prompt = prompt.replace("{global_context}", global_context) # [V1.1.3] Inject Global Context
            prompt = prompt.replace("{code_snippet}", code_snippet[:8000]) 

            
            log.info(f"Generating PoC for {rule_name} in {os.path.basename(file_path)}...")
            
            # The 'prompt' variable is now fully constructed with all placeholders replaced.
            # We pass this as the 'system_prompt' (or 'vuln_prompt') to the LLM client.
            # We pass "" as the code_snippet to analyze_code because we already injected it into the prompt.
            
            context_wrapper = {
                "system_prompt": "You are a Red Team Exploit Developer.",
                "vuln_prompt": prompt, 
                "file_path": file_path
            }
            
            # Note: analyze_code in some clients might try to formatting vuln_prompt if code_snippet is provided.
            # Since we pass prompt (which has no braces left ideally) and empty code_snippet, it should be safe.
            # However, prompt likely contains code with braces.
            # To be safe against client-side formatting, we can pass the whole prompt as system_prompt
            # and empty vuln_prompt, or rely on client implementation.
            # Most clients: f"{system_prompt}\n\n{vuln_prompt}" (no format called if code_snippet is empty or if client checks).
            
            # Let's try passing the full prompt as system_prompt to avoid any client-side formatting magic on '{...}' inside code.
            
            context_wrapper_safe = {
                "system_prompt": prompt,
                "vuln_prompt": "",
                "file_path": file_path
            }
            
            poc_content = self.exploit_llm_client.analyze_code("", context_wrapper_safe)
            
            if not poc_content:
                log.warning("PoC generation returned empty.")
                self._record_pipeline_error(file_path, "exploit_generation", "empty")
                self._metric_add("exploit_errors")
                return self._poc_result(
                    file_path, rule_name, "Unanalyzed",
                    error={"stage": "generation", "reason": "empty"},
                )

            # [FIX] Strip markdown code fences that LLMs often wrap output with.
            # e.g. ```bash\n...\n``` or ```python\n...\n```
            # This ensures the saved file is directly executable without manual editing.
            import re as _re
            # Strategy 1: Extract content inside a fenced block if present
            _fence_match = _re.search(r'^```[a-zA-Z]*\s*\n(.*?)\n```\s*$', poc_content.strip(), _re.DOTALL)
            if _fence_match:
                poc_content = _fence_match.group(1).strip()
                log.debug("Stripped markdown code fence from PoC content.")
            else:
                # Strategy 2: Strip leading/trailing fence markers if partial
                poc_content = _re.sub(r'^```[a-zA-Z]*\s*\n?', '', poc_content.strip())
                poc_content = _re.sub(r'\n?```\s*$', '', poc_content.strip())
                poc_content = poc_content.strip()

            ext = self._detect_poc_extension(poc_content)

            # Use the pre-calculated exploit directory from 'run' if available, otherwise fallback
            if hasattr(self, 'final_exploit_dir') and self.final_exploit_dir:
                 exploit_dir = self.final_exploit_dir
            else:
                 # Fallback (shouldn't happen in normal flow)
                 clean_name = self.apk_name
                 if clean_name.lower().endswith(".apk"):
                     clean_name = clean_name[:-4]
                 exploit_dir = f"output/{clean_name}_exploits"

            os.makedirs(exploit_dir, exist_ok=True)
            
            filename = f"{rule_name}_{os.path.basename(file_path)}{ext}"
            save_path = os.path.join(exploit_dir, filename)
            
            with open(save_path, "w") as f:
                f.write(poc_content)
            
            # [FIX] Auto chmod +x for shell scripts so they are immediately runnable
            if ext == ".sh":
                import stat as _stat
                current_mode = os.stat(save_path).st_mode
                os.chmod(save_path, current_mode | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
                log.debug(f"chmod +x applied to {filename}")

            validation = self._validate_poc_artifact(
                poc_content, ext, rule_name, file_path, code_snippet,
                manifest_context, global_context
            )
            self._metric_add("exploit_generated")
            if validation["status"] == "invalid":
                failed_details = "; ".join(
                    check["detail"] for check in validation["checks"]
                    if check["status"] == "failed"
                )
                log.warning(
                    f"PoC saved for manual review but failed static validation: {save_path}"
                )
                # The artifact is kept on disk for manual review, but it must not be
                # cached: replaying an unusable PoC would make the failure permanent
                # (seen with a reply that was just the word "not", saved as .txt).
                self._invalidate_structured_response(
                    "", context_wrapper_safe, client=self.exploit_llm_client
                )
                self._record_pipeline_error(
                    file_path, "exploit_validation", "invalid_artifact", failed_details
                )
                self._metric_add("exploit_validation_errors")
                return self._poc_result(
                    file_path, rule_name, "validation-error", save_path,
                    error={"stage": "validation", "reason": "invalid_artifact",
                           "detail": failed_details},
                    validation=validation,
                )

            log.success(f"PoC generated and statically validated: {save_path}")
            self._metric_add("exploit_successes")
            return self._poc_result(
                file_path, rule_name, "generated", save_path, validation=validation
            )

        except Exception as e:
            log.error(f"Failed to generate PoC: {e}")
            reason = "timeout" if isinstance(e, TimeoutError) else "exception"
            self._record_pipeline_error(file_path, "exploit_generation", reason, str(e))
            self._metric_add("exploit_errors")
            return self._poc_result(
                file_path, rule_name, "Unanalyzed",
                error={"stage": "generation", "reason": reason, "detail": str(e)},
            )

    def _extract_json_str(self, text: str) -> str:
        """
        Extracts the first balanced JSON object by counting braces, while ignoring
        any braces that appear INSIDE string values.

        String-awareness matters because the `evidence` field routinely contains a
        code snippet with its own `{`/`}` and even nested markdown fences (```java
        ... ```). A naive counter miscounts those braces, and stripping fences with a
        non-greedy regex truncates the JSON at the first inner ``` — both silently
        drop otherwise-valid findings. Respecting string boundaries (and `\\` escapes)
        makes brace-counting robust to arbitrary content inside string values.
        """
        text = text.strip()
        start_idx = text.find('{')
        if start_idx == -1:
            return ""

        balance = 0
        in_string = False
        escaped = False
        for i in range(start_idx, len(text)):
            char = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == '{':
                balance += 1
            elif char == '}':
                balance -= 1
                if balance == 0:
                    return text[start_idx:i+1]
        return ""

    def _parse_llm_response(self, response: str) -> dict:
        """Parses the LLM response string into a dictionary, handling potential formatting issues."""
        import json
        import re
        import ast

        # Strategy 0: String-aware brace counting on the RAW response.
        # find('{') skips any leading ```json fence automatically, and the counter
        # ignores braces / nested ``` fences that live inside string values (e.g. a
        # code snippet in the "evidence" field). Running this FIRST — before any
        # fence stripping — avoids the classic failure where a non-greedy fence regex
        # truncates the JSON at the first ``` found inside a string value.
        json_candidate = self._extract_json_str(response)

        # Strategy 1: Fallback — strip surrounding markdown fences, then retry.
        # Covers responses where the object isn't cleanly balanced in the raw text.
        cleaned_response = re.sub(r'^```[a-zA-Z]*\s*\n?', '', response.strip())
        cleaned_response = re.sub(r'\n?\s*```\s*$', '', cleaned_response).strip()
        if not json_candidate:
            json_candidate = self._extract_json_str(cleaned_response)
        if not json_candidate:
            # Last resort: greedy brace match (may over-capture, tried after the above)
            match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
            json_candidate = match.group(0) if match else cleaned_response

        # List of candidate strings to try parsing
        candidates = [json_candidate, cleaned_response, response]
        
        for candidate in candidates:
            if not candidate: continue
            try:
                # strict=False allows control characters like newlines in strings
                parsed = json.loads(candidate, strict=False)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                # Sub-strategy: Fix common JSON issues (trailing commas)
                try:
                    fixed_json = re.sub(r',\s*([\]\}])', r'\1', candidate)
                    parsed = json.loads(fixed_json, strict=False)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass

                # Sub-strategy: drop backslashes that don't open a valid JSON escape.
                # Models routinely emit \' when quoting code inside "evidence" — legal in
                # Java/Python, illegal in JSON (only \" \\ \/ \b \f \n \r \t \uXXXX are).
                # Since this engine deliberately asks for code in that field, the mistake
                # recurs; one such response was observed poisoning the cache and turning an
                # intermittent failure into a permanent one. Runs only after the strict
                # parses above fail, so well-formed output is never touched.
                try:
                    repaired = re.sub(
                        r'\\(.)',
                        lambda m: m.group(0) if m.group(1) in '"\\/bfnrtu' else m.group(1),
                        candidate,
                    )
                    if repaired != candidate:
                        parsed = json.loads(repaired, strict=False)
                        if isinstance(parsed, dict):
                            log.debug("Parsed LLM response after repairing invalid JSON escapes.")
                            return parsed
                except Exception:
                    pass
                
                # Sub-strategy: Python AST Fallback (Single quotes, etc.)
                try:
                    parsed = ast.literal_eval(candidate)
                    if isinstance(parsed, dict):
                        return parsed
                except:
                    pass

        log.warning(f"Failed to parse LLM response as JSON. Raw: {response[:100]}...")
        return {
                "_parse_failed": True,  # [B] Signals unparseable (non-empty) output to callers.
                "is_vulnerable": False,
                "severity": "Info",
                "confidence": "Low",
                "evidence": "",
                "description": "Failed to parse LLM response. Please review raw output.",
                "attack_scenario": "N/A (Parsing Failed)",
                "attacker_priority": "N/A",
                "recommendation": "Check raw LLM output for details.",
                "false_positive_analysis": "Parsing failed."
            }

    def _file_to_class_dotted(self, file_path: str):
        """Best-effort fully-qualified (dotted) class name from a decompiled file path,
        used to look up the component's AndroidManifest entry. Handles JADX (`.../sources/`)
        and apktool (`.../smali/` or `.../smali_classesN/`) layouts."""
        import re
        p = str(file_path).replace("\\", "/")
        rel = None
        if "/sources/" in p:
            rel = p.split("/sources/", 1)[1]
        else:
            m = re.search(r"/smali(?:_classes\d+)?/", p)
            if m:
                rel = p[m.end():]
        if not rel:
            return None
        for ext in (".java", ".smali"):
            if rel.endswith(ext):
                rel = rel[: -len(ext)]
                break
        return rel.replace("/", ".") if rel else None

    def _manifest_context_for(self, file_path: str) -> str:
        """[B] Inject the component's AndroidManifest entry (exported status, permission,
        intent-filters) into the LLM input so IPC/exported-dependent rules (intent_redirection,
        pending_intent_hijacking, fragment_injection, …) do not have to GUESS reachability.
        The parsing already exists in ManifestParser.get_component_details()."""
        parser = getattr(self, "manifest_parser", None)
        if parser is None:
            return ""
        cls = self._file_to_class_dotted(file_path)
        if not cls:
            return ""
        try:
            details = parser.get_component_details(cls)
        except Exception:
            return ""
        if not details or not details.get("context_str"):
            return ""
        return (
            "\n\n### COMPONENT CONTEXT (from AndroidManifest.xml)\n"
            "Authoritative reachability facts for this class — use them, do NOT guess the exported status:\n"
            + details["context_str"]
        )

    def analyze_file(self, file_path, rules_to_run: list = None):
        results = []
        with open(file_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()
            
        # Context Injection via Call Graph
        external_context = ""
        if self.call_graph_builder and self.settings.analysis.use_cross_reference_context:
            dependency_classes = self.call_graph_builder.get_dependencies(file_path)
            if dependency_classes:
                # Map each summarized file to its class name, so a dependency's summary
                # can be attached whether it was summarized as .java (JADX/hybrid) or
                # .smali (apktool). This is what makes context injection work in hybrid
                # mode, where analyzed files are .java but the call graph is Smali-based.
                class_to_summary = {}
                for summ_path, summ in self.summaries.items():
                    cls = self.call_graph_builder.path_to_class(summ_path)
                    if cls:
                        class_to_summary[cls] = summ

                # Smart Filtering: only inject a dependency's context when we actually
                # have its summary AND its short class name is referenced in this file.
                relevant_summaries = []
                for dep_class in dependency_classes:
                    short_name = dep_class.split("/")[-1]
                    summary = class_to_summary.get(dep_class)

                    # JADX bundles inner classes into the parent .java; fall back to the outer class.
                    if not summary and "$" in dep_class:
                        summary = class_to_summary.get(dep_class.split("$", 1)[0])

                    if summary:
                        java_ref = short_name.replace("$", ".")
                        if short_name in code_snippet or java_ref in code_snippet:
                            relevant_summaries.append(f"- Class {java_ref}: {summary}")

                if relevant_summaries:
                    external_context = "\n\n### EXTERNAL CONTEXT (Dependencies)\n"
                    external_context += "The following are summaries of classes called by this file. Use this to verify inputs/outputs and reduce false positives.\n"
                    external_context += "\n".join(relevant_summaries)
        
        # Keep the complete context for static detection gates. Truncation is only a
        # transport limit for the LLM prompt; using the truncated text for detection
        # could silently drop a source/sink pattern located in the omitted middle.
        rule_gate_context = code_snippet + external_context

        # Combine snippets for the prompt
        full_code_context = rule_gate_context
        # [#5] Cap oversized content before it reaches the LLM.
        full_code_context = self._truncate_for_llm(full_code_context)

        # [B] Reachability context from the manifest. Kept OUT of `full_code_context` so it
        # doesn't affect per-rule pattern gating; appended only to what the LLM actually sees
        # (it's small, so it survives after truncation).
        llm_input = full_code_context + self._manifest_context_for(file_path)

        # [V1.1.7 Library Hunter - Exclusive Mode]
        # Logic: If this is a 3rd party library file, we run ONLY the specialized audit prompt.
        # This saves tokens by not running the 20+ standard rules on generic library code.
        
        is_library_file = False
        library_prefixes = [
            "android/", "androidx/", "com/google/", "kotlin/", 
            "okhttp3/", "retrofit2/", "io/reactivex/", "dagger/",
            "b/b/p/", "b/j/a/"
        ]
        normalized_path = file_path.replace("\\", "/")
        
        for prefix in library_prefixes:
            if prefix in normalized_path:
                is_library_file = True
                break
        
        if self.settings.analysis.scan_libraries and is_library_file:
             log.info(f"Library Scan Triggered for: {os.path.basename(file_path)}")
             prompt_path = "config/prompts/vuln_rules/library_vulnerability.yaml"
             if os.path.exists(prompt_path):
                 with open(prompt_path, "r") as f:
                     prompt_data = yaml.safe_load(f)
                 
                 # [V1.1.7 Optimization] Hybrid Filter
                 # Check regex pattern before calling LLM
                 if self.settings.analysis.filter_mode != "llm_only":
                     pattern = prompt_data.get("detection_pattern")
                     if pattern:
                         import re
                         if not re.search(pattern, rule_gate_context, re.IGNORECASE | re.DOTALL):
                             log.debug(f"Skipping library file {os.path.basename(file_path)}: No suspicious pattern found.")
                             return results

                 # Prepare Context
                 system_prompt = self._load_system_prompt()
                 
                 context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": prompt_data["prompt"] + JSON_ONLY_SUFFIX,
                    "file_path": file_path,
                    "expect_json": True  # [A] Rule analysis requires JSON output
                 }

                 # Run Analysis
                 try:
                     self._metric_add("deep_rule_checks")
                     raw_result = self.llm_client.analyze_code(llm_input, context)

                     # [FIX #2] A failed LLM call must not read as a clean library.
                     if self._is_failed_response(raw_result):
                         self._record_deep_rule_outcome("Error")
                         log.warning(f"LLM library scan failed for {os.path.basename(file_path)}; marking as Error (not clean).")
                         results.append(self._build_error_result(file_path, "library_vulnerability", "Library Hunter"))
                         return results

                     parsed_result = self._parse_llm_response(raw_result)

                     # [B] Non-empty but unparseable (e.g. prose from a local model) -> Error, not clean.
                     if parsed_result.get("_parse_failed"):
                         self._record_deep_rule_outcome("Error")
                         log.warning(f"Unparseable LLM output for library scan of {os.path.basename(file_path)}; marking as Error.")
                         self._invalidate_structured_response(llm_input, context)
                         results.append(self._build_error_result(
                             file_path,
                             "library_vulnerability",
                             "Library Hunter",
                             reason="unparseable",
                             raw_response=raw_result,
                         ))
                         return results

                     status = self.get_status(parsed_result)

                     if status == "Error":
                         self._record_deep_rule_outcome("Error")
                         log.warning(
                             f"Invalid LLM verdict for library scan of {os.path.basename(file_path)}; "
                             "marking as Error (not clean)."
                         )
                         results.append(self._build_error_result(
                             file_path,
                             "library_vulnerability",
                             "Library Hunter",
                             reason="invalid_verdict",
                             raw_response=raw_result,
                         ))
                         return results

                     if status == "Vulnerable":
                         parsed_result = self._enrich_result("library_vulnerability", parsed_result)
                         if self.settings.analysis.generate_exploit:
                              self.vulnerability_findings.append({
                                  "file_path": file_path,
                                  "code_snippet": full_code_context,
                                  "vuln_description": parsed_result.get("description", ""),
                                  "rule_name": "library_vulnerability"
                              })

                         results.append({
                            "file": file_path,
                            "rule": "library_vulnerability",
                            "vulnerability": "Library Hunter",
                            "status": status,
                            "result": parsed_result
                         })
                     self._record_deep_rule_outcome(status)
                 except Exception as e:
                     self._record_deep_rule_outcome("Error")
                     log.error(f"Library Scan failed for {file_path}: {e}")
                     reason = "timeout" if isinstance(e, TimeoutError) else "exception"
                     results.append(self._build_error_result(
                         file_path,
                         "library_vulnerability",
                         "Library Hunter",
                         reason=reason,
                         detail=str(e),
                     ))
             
             # [CRITICAL OPTIMIZATION] Early Return!
             # We assume standard logic rules (like 'Intent Spoofing' in App Logic) are less relevant 
             # for granular library internals, or are covered by the general 'Library Audit' prompt.
             return results

        for rule_name, enabled in self.settings.rules.model_dump().items():
            if enabled and rule_name not in DEDICATED_PASS_RULES:
                if rules_to_run is not None and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                try:
                    with open(prompt_path, "r") as f:
                        prompt_data = yaml.safe_load(f)
                except Exception as exc:
                    log.error(f"Could not load rule '{rule_name}': {exc}")
                    results.append(self._build_error_result(
                        file_path,
                        rule_name,
                        rule_name,
                        reason="exception",
                        detail=f"rule config: {exc}",
                    ))
                    continue

                # [FIX #1] Skip this rule's LLM call if its detection pattern doesn't match.
                if not self._rule_should_run(rule_name, prompt_data, rule_gate_context):
                    log.debug(f"Gated: rule '{rule_name}' skipped for {os.path.basename(file_path)} (no pattern match).")
                    continue

                # --- MASVS CONTEXT INJECTION (LITE RAG) ---
                system_prompt = self._load_system_prompt()
                
                
                # Check if this rule maps to a MASVS ID
                if rule_name in self.masvs_mapping:
                    masvs_info_data = self.masvs_mapping[rule_name]
                    masvs_id = masvs_info_data.get("masvs_id", "Unknown")
                    masvs_desc = masvs_info_data.get("description", "No description available.")
                    
                    # Append guidance to the system prompt
                    system_prompt += f"\n\n### OWASP MASVS GUIDANCE\n"
                    system_prompt += f"This analysis relates to **{masvs_id}**.\n"
                    system_prompt += f"Standard: \"{masvs_desc}\"\n"
                    system_prompt += f"Ensure your verification aligns strictly with this standard."

                # [A] Rule prompts are language-agnostic ("Java or Smali"), so the old
                # vuln_prompt.replace("smali","java") hack has been retired.
                vuln_prompt = prompt_data["prompt"]

                context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": vuln_prompt + JSON_ONLY_SUFFIX,
                    "file_path": file_path,
                    "expect_json": True  # [A] Rule analysis requires JSON output
                }

                # Pass the ENRICHED context (code + cross-ref + manifest reachability)
                try:
                    self._metric_add("deep_rule_checks")
                    raw_result = self.llm_client.analyze_code(llm_input, context)
                except Exception as exc:
                    self._record_deep_rule_outcome("Error")
                    reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
                    log.error(
                        f"LLM analysis raised {reason} for rule '{rule_name}' on "
                        f"{os.path.basename(file_path)}: {exc}"
                    )
                    results.append(self._build_error_result(
                        file_path,
                        rule_name,
                        prompt_data["name"],
                        reason=reason,
                        detail=str(exc),
                    ))
                    continue

                # [FIX #2] Distinguish a failed LLM call from a genuine "clean" verdict.
                if self._is_failed_response(raw_result):
                    self._record_deep_rule_outcome("Error")
                    log.warning(f"LLM analysis failed for rule '{rule_name}' on {os.path.basename(file_path)}; marking as Error (not clean).")
                    results.append(self._build_error_result(file_path, rule_name, prompt_data["name"]))
                    continue

                parsed_result = self._parse_llm_response(raw_result)

                # [B] Non-empty but unparseable (e.g. prose from a local model) -> Error, not clean.
                if parsed_result.get("_parse_failed"):
                    self._record_deep_rule_outcome("Error")
                    log.warning(f"Unparseable LLM output for rule '{rule_name}' on {os.path.basename(file_path)}; marking as Error.")
                    self._invalidate_structured_response(llm_input, context)
                    results.append(self._build_error_result(
                        file_path,
                        rule_name,
                        prompt_data["name"],
                        reason="unparseable",
                        raw_response=raw_result,
                    ))
                    continue

                status = self.get_status(parsed_result)

                if status == "Error":
                    self._record_deep_rule_outcome("Error")
                    log.warning(
                        f"Invalid LLM verdict for rule '{rule_name}' on {os.path.basename(file_path)}; "
                        "marking as Error (not clean)."
                    )
                    results.append(self._build_error_result(
                        file_path,
                        rule_name,
                        prompt_data["name"],
                        reason="invalid_verdict",
                        raw_response=raw_result,
                    ))
                    continue

                self._record_deep_rule_outcome(status)

                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)
                    
                    # Instead of generating PoC immediately, we store the finding.
                    if self.settings.analysis.generate_exploit:
                         self.vulnerability_findings.append({
                             "file_path": file_path,
                             "code_snippet": full_code_context,
                             "vuln_description": parsed_result.get("description", ""),
                             "rule_name": rule_name
                         })

                results.append({
                    "file": file_path,
                    "rule": rule_name,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result # Store the full structured object
                })
        return results

    def analyze_manifest(self, manifest_path, rules_to_run: list = None):
        results = []
        with open(manifest_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        for rule_name in MANIFEST_RULES:
            if getattr(self.settings.rules, rule_name):
                if rules_to_run is not None and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                try:
                    with open(prompt_path, "r") as f:
                        prompt_data = yaml.safe_load(f)
                except Exception as exc:
                    log.error(f"Could not load manifest rule '{rule_name}': {exc}")
                    results.append(self._build_error_result(
                        manifest_path,
                        rule_name,
                        rule_name,
                        reason="exception",
                        detail=f"rule config: {exc}",
                    ))
                    continue

                context = {
                    "system_prompt": self._load_system_prompt(),
                    "vuln_prompt": prompt_data["prompt"] + JSON_ONLY_SUFFIX,
                    "file_path": manifest_path,
                    "expect_json": True  # [A] Rule analysis requires JSON output
                }

                try:
                    self._metric_add("manifest_rule_checks")
                    raw_result = self.llm_client.analyze_code(code_snippet, context)
                except Exception as exc:
                    reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
                    log.error(f"Manifest rule '{rule_name}' raised {reason}: {exc}")
                    results.append(self._build_error_result(
                        manifest_path,
                        rule_name,
                        prompt_data["name"],
                        reason=reason,
                        detail=str(exc),
                    ))
                    continue

                # [FIX #2] Failed manifest analysis is not a clean verdict.
                if self._is_failed_response(raw_result):
                    log.warning(f"LLM analysis failed for manifest rule '{rule_name}'; marking as Error (not clean).")
                    results.append(self._build_error_result(manifest_path, rule_name, prompt_data["name"]))
                    continue

                parsed_result = self._parse_llm_response(raw_result)

                # [B] Non-empty but unparseable output -> Error, not clean.
                if parsed_result.get("_parse_failed"):
                    log.warning(f"Unparseable LLM output for manifest rule '{rule_name}'; marking as Error.")
                    self._invalidate_structured_response(code_snippet, context)
                    results.append(self._build_error_result(
                        manifest_path,
                        rule_name,
                        prompt_data["name"],
                        reason="unparseable",
                        raw_response=raw_result,
                    ))
                    continue

                status = self.get_status(parsed_result)

                if status == "Error":
                    log.warning(
                        f"Invalid LLM verdict for manifest rule '{rule_name}'; "
                        "marking as Error (not clean)."
                    )
                    results.append(self._build_error_result(
                        manifest_path,
                        rule_name,
                        prompt_data["name"],
                        reason="invalid_verdict",
                        raw_response=raw_result,
                    ))
                    continue

                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)
                    
                    if self.settings.analysis.generate_exploit:
                         self.vulnerability_findings.append({
                             "file_path": manifest_path,
                             "code_snippet": code_snippet,
                             "vuln_description": parsed_result.get("description", ""),
                             "rule_name": rule_name
                         })

                results.append({
                    "file": manifest_path,
                    "rule": rule_name,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result
                })
        return results

    def analyze_strings_xml(self, decompiled_dir: str, rules_to_run: list = None):
        """Scans res/values/strings.xml for hardcoded secrets."""
        results = []
        rule_name = "hardcoded_secrets_xml"
        
        if not getattr(self.settings.rules, rule_name):
            return []

        if rules_to_run is not None and rule_name not in rules_to_run:
            return []

        # Find strings.xml
        strings_path = None
        for root, _, files in os.walk(decompiled_dir):
            if "strings.xml" in files:
                # Prioritize res/values/strings.xml
                potential = os.path.join(root, "strings.xml")
                if "values" in root.split(os.sep): 
                     strings_path = potential
                     break
                # Fallback to any strings.xml if not in valus (unlikely but possible)
                if not strings_path:
                    strings_path = potential

        if not strings_path:
            log.warning("strings.xml not found in decompiled output.")
            return []

        log.info(f"Analyzing {strings_path} for Hardcoded Secrets...")
        
        with open(strings_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
        with open(prompt_path, "r") as f:
            prompt_data = yaml.safe_load(f)

        context = {
            "system_prompt": self._load_system_prompt(),
            "vuln_prompt": prompt_data["prompt"] + JSON_ONLY_SUFFIX,
            "file_path": strings_path,
            "expect_json": True  # [A] Rule analysis requires JSON output
        }

        try:
            self._metric_add("strings_rule_checks")
            raw_result = self.llm_client.analyze_code(code_snippet, context)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            log.error(f"Strings rule '{rule_name}' raised {reason}: {exc}")
            return [self._build_error_result(
                strings_path,
                rule_name,
                prompt_data["name"],
                reason=reason,
                detail=str(exc),
            )]

        # [FIX #2] Failed strings.xml analysis is not a clean verdict.
        if self._is_failed_response(raw_result):
            log.warning(f"LLM analysis failed for '{rule_name}' on strings.xml; marking as Error (not clean).")
            return [self._build_error_result(strings_path, rule_name, prompt_data["name"])]

        parsed_result = self._parse_llm_response(raw_result)

        # [B] Non-empty but unparseable output -> Error, not clean.
        if parsed_result.get("_parse_failed"):
            log.warning(f"Unparseable LLM output for '{rule_name}' on strings.xml; marking as Error.")
            self._invalidate_structured_response(code_snippet, context)
            return [self._build_error_result(
                strings_path,
                rule_name,
                prompt_data["name"],
                reason="unparseable",
                raw_response=raw_result,
            )]

        status = self.get_status(parsed_result)

        if status == "Error":
            log.warning(
                f"Invalid LLM verdict for '{rule_name}' on strings.xml; "
                "marking as Error (not clean)."
            )
            return [self._build_error_result(
                strings_path,
                rule_name,
                prompt_data["name"],
                reason="invalid_verdict",
                raw_response=raw_result,
            )]

        if status == "Vulnerable":
            # [V1.1.3] DEFERRED GENERATION
            if self.settings.analysis.generate_exploit:
                    self.vulnerability_findings.append({
                        "file_path": strings_path,
                        "code_snippet": code_snippet,
                        "vuln_description": parsed_result.get("description", ""),
                        "rule_name": rule_name
                    })

        results.append({
            "file": strings_path,
            "rule": rule_name,
            "vulnerability": prompt_data["name"],
            "status": status,
            "result": parsed_result
        })
        return results

    def _summary_chunks_for_file(self, file_path: str) -> dict:
        """Read one file and return the established ordered summary units."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as exc:
            return {
                "chunks": [],
                "errors": [{"reason": "file_read_error", "detail": str(exc)}],
            }

        # Preserve the established chunk contract exactly: Java is one unit while a
        # multi-class Smali file keeps every class in original order.
        if file_path.endswith(".smali"):
            chunks = [".class " + c for c in content.split(".class ") if c.strip()]
        else:
            chunks = [content] if content.strip() else []
        return {"chunks": chunks, "errors": []}

    def _summarize_unit(self, file_path: str, chunk: str, summarize_prompt: str) -> dict:
        """Run one established summary call; also used as mandatory batch fallback."""
        context = {
            "system_prompt": "",
            "vuln_prompt": summarize_prompt,
            "file_path": file_path,
        }
        try:
            summary = self.llm_client.analyze_code(self._truncate_for_llm(chunk), context)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            return {
                "summary": "",
                "errors": [{"reason": reason, "detail": str(exc)}],
                "calls": 1,
            }
        log.debug(f"Summary for {file_path}: {summary}")
        if summary and summary.strip():
            return {"summary": summary.strip(), "errors": [], "calls": 1}
        return {
            "summary": "",
            "errors": [{"reason": "empty", "detail": ""}],
            "calls": 1,
        }

    def _summarize_file(self, file_path: str, summarize_prompt: str) -> dict:
        """Summarize one file without mutating shared scan/report state."""
        prepared = self._summary_chunks_for_file(file_path)
        errors = list(prepared["errors"])
        call_count = 0
        file_summaries = []
        for chunk in prepared["chunks"]:
            outcome = self._summarize_unit(file_path, chunk, summarize_prompt)
            call_count += outcome["calls"]
            errors.extend(outcome["errors"])
            if outcome["summary"]:
                file_summaries.append(outcome["summary"])
        return {
            "summary": "\n".join(file_summaries),
            "errors": errors,
            "calls": call_count,
        }

    @staticmethod
    def _summary_unit_id(file_index: int, file_path: str, chunk_index: int) -> str:
        """Return a stable opaque id that cannot collide on basename alone."""
        import hashlib
        identity = f"{file_index}\0{file_path}\0{chunk_index}".encode(
            "utf-8", errors="replace"
        )
        return "summary_" + hashlib.sha256(identity).hexdigest()

    def _invalidate_structured_response(self, payload: str, context: dict, client=None):
        """Best-effort removal of a cached response that higher-level validation rejected.

        The cache can only tell whether a response was non-empty; it cannot know whether
        the engine could actually USE it. Without this, one unparseable (but non-empty)
        reply is cached forever and replayed on every later run, turning a transient
        provider glitch into a permanent one — observed twice in practice: a reply using
        the invalid \' JSON escape, and a PoC reply that was literally the word "not".
        """
        invalidator = getattr(client or self.llm_client, "invalidate", None)
        if not callable(invalidator):
            return
        try:
            invalidator(payload, context)
        except Exception as exc:
            log.debug(f"Could not invalidate invalid summary batch response: {exc}")

    def _fallback_summary_batch(self, units: list, summarize_prompt: str, detail: str) -> dict:
        """Retry every supplied unit with the established individual contract."""
        unit_results = {}
        calls = 0
        for unit in units:
            result = self._summarize_unit(
                unit["file_path"], unit["chunk"], summarize_prompt
            )
            unit_results[unit["id"]] = result
            calls += result["calls"]
        return {
            "unit_results": unit_results,
            "calls": calls,
            "valid_items": 0,
            "fallback_items": len(units),
            "batch_failed": True,
            "batch_failure_detail": detail,
        }

    def _summarize_batch(self, units: list, summarize_prompt: str) -> dict:
        """Summarize strict id->summary JSON and retry missing items individually."""
        import json

        payload = json.dumps(
            {
                "items": [
                    {"id": unit["id"], "code": self._truncate_for_llm(unit["chunk"])}
                    for unit in units
                ]
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        context = {
            "system_prompt": "",
            "vuln_prompt": summarize_prompt + SUMMARY_BATCH_SUFFIX,
            "file_path": "summary_batch:" + units[0]["id"],
        }
        try:
            raw_result = self.llm_client.analyze_code(payload, context)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            fallback = self._fallback_summary_batch(
                units, summarize_prompt, f"{reason}: {exc}"
            )
            fallback["calls"] += 1
            return fallback

        if self._is_failed_response(raw_result):
            fallback = self._fallback_summary_batch(units, summarize_prompt, "empty")
            fallback["calls"] += 1
            return fallback

        parsed = self._parse_llm_response(raw_result)
        expected_ids = {unit["id"] for unit in units}
        structural_failure = (
            parsed.get("_parse_failed") is True
            or any(key not in expected_ids for key in parsed)
        )
        if structural_failure:
            self._invalidate_structured_response(payload, context)
            fallback = self._fallback_summary_batch(
                units, summarize_prompt, "invalid batch JSON mapping"
            )
            fallback["calls"] += 1
            return fallback

        unit_results = {}
        fallback_units = []
        valid_items = 0
        for unit in units:
            summary = parsed.get(unit["id"])
            if isinstance(summary, str) and summary.strip():
                unit_results[unit["id"]] = {
                    "summary": summary.strip(),
                    "errors": [],
                    "calls": 0,
                }
                valid_items += 1
            else:
                fallback_units.append(unit)

        calls = 1
        if fallback_units:
            # Partial output is usable for this run but is not a persistent success.
            self._invalidate_structured_response(payload, context)
            fallback = self._fallback_summary_batch(
                fallback_units, summarize_prompt, "missing or invalid batch item"
            )
            unit_results.update(fallback["unit_results"])
            calls += fallback["calls"]

        return {
            "unit_results": unit_results,
            "calls": calls,
            "valid_items": valid_items,
            "fallback_items": len(fallback_units),
            "batch_failed": bool(fallback_units),
            "batch_failure_detail": "missing or invalid batch item" if fallback_units else "",
        }

    def _summarize_files_batched(
        self,
        files_to_process: list,
        summarize_prompt: str,
        batch_size: int,
        worker_count: int,
    ) -> list:
        """Run opt-in batch summaries and restore exact file/chunk ordering."""
        # Ensure direct/internal callers receive the complete metric schema too.
        for metric in (
            "summary_batch_requests",
            "summary_batch_items",
            "summary_batch_valid_items",
            "summary_batch_fallback_items",
            "summary_batch_failures",
        ):
            self._metric_add(metric, 0)
        prepared_files = []
        units = []
        for file_index, file_path in enumerate(files_to_process):
            prepared = self._summary_chunks_for_file(file_path)
            prepared_files.append({
                "parts": [None] * len(prepared["chunks"]),
                "errors": list(prepared["errors"]),
            })
            for chunk_index, chunk in enumerate(prepared["chunks"]):
                units.append({
                    "id": self._summary_unit_id(file_index, file_path, chunk_index),
                    "file_index": file_index,
                    "file_path": file_path,
                    "chunk_index": chunk_index,
                    "chunk": chunk,
                })

        groups = [
            units[index:index + batch_size]
            for index in range(0, len(units), batch_size)
        ]
        # A trailing singleton uses the established individual prompt/cache key;
        # wrapping one item in a batch cannot save a call and only adds parse risk.
        batches = [group for group in groups if len(group) > 1]
        singleton_units = [group[0] for group in groups if len(group) == 1]
        batch_outcomes = [None] * len(batches)
        if worker_count == 1 or len(batches) <= 1:
            for index, batch in enumerate(batches):
                batch_outcomes[index] = self._summarize_batch(batch, summarize_prompt)
        else:
            log.info(
                f"Summarizing {len(units)} item(s) in {len(batches)} batch(es) "
                f"with {worker_count} worker(s)..."
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_index = {
                    executor.submit(self._summarize_batch, batch, summarize_prompt): index
                    for index, batch in enumerate(batches)
                }
                for future in track(
                    concurrent.futures.as_completed(future_to_index),
                    total=len(future_to_index),
                    description="Summarizing batches...",
                    console=console,
                ):
                    index = future_to_index[future]
                    try:
                        batch_outcomes[index] = future.result()
                    except Exception as exc:
                        batch_outcomes[index] = self._fallback_summary_batch(
                            batches[index], summarize_prompt, f"worker exception: {exc}"
                        )

        self._metric_add("summary_batch_requests", len(batches))
        self._metric_add("summary_batch_items", sum(len(batch) for batch in batches))
        for batch, outcome in zip(batches, batch_outcomes):
            if outcome is None:
                outcome = self._fallback_summary_batch(
                    batch, summarize_prompt, "missing batch worker result"
                )
            self._metric_add("summarization_calls", outcome["calls"])
            self._metric_add("summary_batch_valid_items", outcome["valid_items"])
            self._metric_add("summary_batch_fallback_items", outcome["fallback_items"])
            if outcome["batch_failed"]:
                self._metric_add("summary_batch_failures")
            for unit in batch:
                unit_result = outcome["unit_results"][unit["id"]]
                state = prepared_files[unit["file_index"]]
                state["parts"][unit["chunk_index"]] = unit_result["summary"]
                state["errors"].extend(unit_result["errors"])

        for unit in singleton_units:
            unit_result = self._summarize_unit(
                unit["file_path"], unit["chunk"], summarize_prompt
            )
            self._metric_add("summarization_calls", unit_result["calls"])
            state = prepared_files[unit["file_index"]]
            state["parts"][unit["chunk_index"]] = unit_result["summary"]
            state["errors"].extend(unit_result["errors"])

        return [
            {
                "summary": "\n".join(part for part in state["parts"] if part),
                "errors": state["errors"],
                "calls": 0,
            }
            for state in prepared_files
        ]

    def summarize_chunks(
        self,
        decompiled_dir: str,
        file_list: list = None,
        summary_workers: int = 1,
        summary_batch_size: int = 1,
    ):
        log.info("Starting code summarization...")
        summaries = {}
        summarize_prompt = self._load_summarize_prompt()

        files_to_process = []
        if file_list:
             files_to_process = file_list
        else:
            for root, _, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith(".smali"):
                        files_to_process.append(os.path.join(root, file))

        # Config validation bounds production values to 1..32. Clamp again here so
        # direct/internal callers cannot accidentally create an unbounded executor.
        worker_count = max(1, min(32, int(summary_workers or 1)))
        batch_size = max(1, min(32, int(summary_batch_size or 1)))
        outcomes = [None] * len(files_to_process)

        if batch_size > 1:
            outcomes = self._summarize_files_batched(
                files_to_process,
                summarize_prompt,
                batch_size,
                worker_count,
            )
        elif worker_count == 1:
            for index, file_path in enumerate(track(
                files_to_process,
                description="Summarizing code...",
                console=console,
            )):
                outcomes[index] = self._summarize_file(file_path, summarize_prompt)
        else:
            log.info(f"Summarizing code with {worker_count} worker(s)...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
                future_to_index = {
                    executor.submit(self._summarize_file, file_path, summarize_prompt): index
                    for index, file_path in enumerate(files_to_process)
                }
                for future in track(
                    concurrent.futures.as_completed(future_to_index),
                    total=len(future_to_index),
                    description="Summarizing code...",
                    console=console,
                ):
                    index = future_to_index[future]
                    try:
                        outcomes[index] = future.result()
                    except Exception as exc:
                        # Unexpected worker failures remain fail-open. KeyboardInterrupt
                        # and other BaseException subclasses are deliberately not caught,
                        # so run() cannot publish a false Completed report on interruption.
                        outcomes[index] = {
                            "summary": "",
                            "errors": [{"reason": "exception", "detail": str(exc)}],
                            "calls": 0,
                        }

        # Merge only on the main thread and strictly in the original candidate order.
        # This preserves summary dict order used by dependency/app/attack-surface context.
        for index, file_path in enumerate(files_to_process):
            outcome = outcomes[index] or {
                "summary": "",
                "errors": [{"reason": "exception", "detail": "missing worker result"}],
                "calls": 0,
            }
            self._metric_add("summarization_calls", outcome["calls"])
            for error in outcome["errors"]:
                reason = error["reason"]
                detail = error.get("detail", "")
                if reason == "empty":
                    log.warning(
                        f"Summarization returned an empty response for {file_path}; "
                        "candidate will be kept."
                    )
                else:
                    log.warning(
                        f"Summarization failed for {file_path}; candidate will be kept: "
                        f"{detail or reason}"
                    )
                self._record_pipeline_error(
                    file_path, "summarization", reason, detail
                )
            summaries[file_path] = outcome["summary"]

        log.success("Code summarization complete.")
        return summaries

    def identify_risky_chunks(self, summaries: dict):
        log.info("Identifying risky code chunks...")
        risky_files = []
        identify_risk_prompt = self._load_identify_risk_prompt()

        for file_path, summary in track(summaries.items(), total=len(summaries), description="Identifying risky files...", console=console):
            context = {
                "system_prompt": "",
                "vuln_prompt": identify_risk_prompt,
                "file_path": file_path
            }
            
            # A missing summary is already an analysis failure. Do not ask the triage
            # model to judge empty evidence; keep the candidate for rule analysis.
            if not summary or not summary.strip():
                self._record_pipeline_error(file_path, "risk_triage", "missing_summary")
                self._metric_add("triage_errors")
                risky_files.append(file_path)
                log.debug(f"Fail-open risk triage for {file_path}: summary unavailable.")
                continue

            try:
                self._metric_add("risk_triage_calls")
                response = self.llm_client.analyze_code(summary, context)
            except Exception as exc:
                log.warning(f"Risk triage failed for {file_path}; candidate will be kept: {exc}")
                reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
                self._record_pipeline_error(file_path, "risk_triage", reason, str(exc))
                self._metric_add("triage_errors")
                risky_files.append(file_path)
                continue

            normalized = response.strip().lower() if response else ""
            if normalized.startswith("yes"):
                self._metric_add("triage_yes")
                risky_files.append(file_path)
                log.debug(f"Identified risky file: {file_path}")
            elif normalized.startswith("no"):
                self._metric_add("triage_no")
                # A valid negative remains useful for ordering, but hybrid selection
                # no longer treats it as authority to discard a static candidate.
                log.debug(f"Risk triage deprioritized file: {file_path}")
            else:
                reason = "empty" if not normalized else "unparseable"
                log.warning(f"Risk triage returned {reason} output for {file_path}; candidate will be kept.")
                self._record_pipeline_error(file_path, "risk_triage", reason)
                self._metric_add("triage_errors")
                risky_files.append(file_path)

        log.success(f"Identified {len(risky_files)} risky files.")
        return risky_files

    @staticmethod
    def _select_deep_scan_targets(candidates: list, llm_risky: list, pattern_risky: list = None) -> list:
        """Prioritize triage/static hits without allowing triage to delete candidates."""
        return list(dict.fromkeys(llm_risky + (pattern_risky or []) + candidates))

    def _pattern_matched_files(self, files: list, patterns: list, app_package_name: str = "") -> list:
        """In-scope files whose content matches an enabled rule's detection_pattern.

        A static pattern hit is a STRONG signal, so these files must reach the deep-scan
        (where per-rule gating + the rule LLM decide the verdict) and must NOT be dropped
        by the coarse LLM risk-triage. Layer-2 bug this fixes: ZipSlipActivity matched the
        zip_slip pattern yet identify_risky_chunks judged it "not risky" and dropped it
        before any rule ran. The caller has already applied `_is_relevant_file`; repeating
        scope here using only the exact manifest-package path lost sibling and obfuscated
        app namespaces. `app_package_name` remains for call compatibility only.
        """
        import re
        compiled = []
        for p in patterns:
            try:
                compiled.append(re.compile(p, re.IGNORECASE | re.DOTALL))
            except re.error:
                continue
        if not compiled:
            return []
        hits = []
        for f in files:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                self._record_pipeline_error(f, "static_pattern_rescue", "file_read_error")
                continue
            if any(rx.search(content) for rx in compiled):
                hits.append(f)
        return hits

    def summarize_app(self, manifest_path: str, summaries: dict):
        log.info("Summarizing application capabilities...")

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = f.read()

            summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())

            prompt = self._load_app_summary_prompt().format(manifest=manifest, summaries=summaries_text)
            # Escape curly braces to prevent double formatting issues in analyze_code
            prompt = prompt.replace("{", "{{").replace("}", "}}")

            context = {
                "system_prompt": "",
                "vuln_prompt": prompt,
                "file_path": manifest_path
            }

            self._metric_add("app_summary_calls")
            app_summary = self.llm_client.analyze_code("", context)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            log.error(f"Application summarization raised {reason}: {exc}")
            self._record_pipeline_error(manifest_path, "app_summary", reason, str(exc))
            return ""

        if self._is_failed_response(app_summary):
            log.warning("Application summarization returned an empty response.")
            self._record_pipeline_error(manifest_path, "app_summary", "empty")
            return ""

        log.success("Application capabilities summarized.")
        return app_summary

    def generate_attack_surface_map(self, manifest_path: str, summaries: dict):
        """[v1.3.0] Returns a compact, structured INVENTORY dict (exported components,
        deep links, network/IPC/file-io/deserialization/reflection signals, manifest
        flags) — not a narrative report. A downstream tool (e.g. an HTML report) is
        expected to render this into bullets/tables itself. Kept small on purpose:
        the per-file vulnerability findings already carry the detailed explanations."""
        log.info("Generating attack surface map...")

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = f.read()

            summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())

            prompt = self._load_attack_surface_prompt().format(manifest=manifest, summaries=summaries_text)
            # Escape curly braces to prevent double formatting issues in analyze_code
            prompt = prompt.replace("{", "{{").replace("}", "}}")

            context = {
                "system_prompt": "",
                "vuln_prompt": prompt,
                "file_path": manifest_path,
                "expect_json": True  # force JSON mode on providers that support it (e.g. Ollama)
            }

            self._metric_add("attack_surface_calls")
            raw_result = self.llm_client.analyze_code("", context)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            log.error(f"Attack surface map generation raised {reason}: {exc}")
            self._record_pipeline_error(manifest_path, "attack_surface", reason, str(exc))
            return {"error": f"Attack surface generation failed ({reason})"}

        if self._is_failed_response(raw_result):
            log.warning("Attack surface map generation failed (empty LLM response).")
            self._record_pipeline_error(manifest_path, "attack_surface", "empty")
            return {"error": "LLM call failed (empty response)"}

        parsed = self._parse_llm_response(raw_result)
        if parsed.get("_parse_failed"):
            log.warning("Attack surface map response was not valid JSON.")
            self._record_pipeline_error(
                manifest_path,
                "attack_surface",
                "unparseable",
                raw_response=raw_result,
            )
            return {"error": "Unparseable LLM output", "raw": raw_result[:500]}

        log.success("Attack surface map generated.")
        return parsed

    def _find_smali_fallback(self, java_path: str, output_dir: str) -> str:
        """Helper to find corresponding smali file for a java file."""
        # Java: output/src_jadx/com/example/MainActivity.java
        # Smali: output/smali/com/example/MainActivity.smali
        # This is a heuristic translation
        try:
             # Remove prefix up to package
             rel_path = java_path.split("sources/")[-1] 
             if not rel_path: return None
             
             smali_path = os.path.join(output_dir, "smali", rel_path.replace(".java", ".smali"))
             if os.path.exists(smali_path):
                 return smali_path
        except:
             pass
        return None

    def _collect_static_candidates(
        self,
        decomp_mode: str,
        smali_dir: str,
        java_dir: str,
        rule_keywords: list,
        rule_patterns: list,
        strict_mode: bool,
    ) -> list:
        """Collect standard rule candidates, then add library-specific candidates.

        `scan_libraries` is additive: enabling it must never replace the candidate set
        built from active vulnerability rules.
        """
        if decomp_mode in ("jadx", "hybrid") and os.path.exists(java_dir):
            scan_root, source_mode = java_dir, "java"
        else:
            if decomp_mode == "jadx":
                log.error("JADX sources not found. Falling back to Smali.")
            scan_root, source_mode = smali_dir, "smali"

        standard_filter = CodeFilter(
            scan_root,
            mode=source_mode,
            additional_keywords=rule_keywords,
            additional_regex=rule_patterns,
            strict_mode=strict_mode,
        )
        standard_targets = standard_filter.find_high_value_targets()

        if not self.settings.analysis.scan_libraries:
            return standard_targets

        library_patterns = []
        lib_prompt_path = "config/prompts/vuln_rules/library_vulnerability.yaml"
        if os.path.exists(lib_prompt_path):
            with open(lib_prompt_path, "r") as f:
                library_data = yaml.safe_load(f) or {}
            if library_data.get("detection_pattern"):
                library_patterns.append(library_data["detection_pattern"])

        log.info("Library Hunter Mode: adding strict library candidates to the standard candidate set.")
        library_filter = CodeFilter(
            scan_root,
            mode=source_mode,
            additional_keywords=[],
            additional_regex=library_patterns,
            strict_mode=True,
        )
        library_targets = library_filter.find_high_value_targets()
        return list(dict.fromkeys(standard_targets + library_targets))

    def _resolve_active_rules(self, rules: str = None) -> list:
        """Return enabled rules, optionally narrowed by an explicit CLI selection.

        Explicit `--rules` is an operator-requested scope restriction, not permission
        to enable rules disabled in settings. Whitespace is normalized, while rule names
        remain case-sensitive and otherwise unchanged.
        """
        configured = self.settings.rules.model_dump()
        enabled_rules = [name for name, enabled in configured.items() if enabled]
        if rules is None:
            return enabled_rules

        requested = list(dict.fromkeys(part.strip() for part in rules.split(",") if part.strip()))
        known = set(configured)
        unknown = [name for name in requested if name not in known]
        if unknown:
            log.warning(f"Ignoring unknown explicitly requested rule(s): {', '.join(unknown)}")

        disabled = [name for name in requested if name in known and not configured[name]]
        if disabled:
            log.warning(
                "Explicitly requested rule(s) disabled in settings and therefore not active: "
                + ", ".join(disabled)
            )

        requested_set = set(requested)
        return [name for name in enabled_rules if name in requested_set]

    def _load_rule_signals(self, active_rules: list) -> tuple:
        """Load candidate keywords/regex only for the rules active in this scan."""
        extra_keywords = []
        extra_regex = []
        for rule_name in active_rules:
            if rule_name in DEDICATED_PASS_RULES:
                continue
            try:
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    rule_data = yaml.safe_load(f) or {}
                extra_keywords.extend(rule_data.get("keywords") or [])
                if rule_data.get("detection_pattern"):
                    extra_regex.append(rule_data["detection_pattern"])
                elif (rule_data.get("static_analysis") or {}).get("patterns"):
                    extra_regex.extend(rule_data["static_analysis"]["patterns"])
            except Exception as exc:
                log.warning(f"Could not load matching logic from {rule_name}: {exc}")
                self._record_pipeline_error(
                    f"config/prompts/vuln_rules/{rule_name}.yaml",
                    "rule_signal_loading",
                    "exception",
                    str(exc),
                )

        # Stable additive deduplication: preserve every distinct signal and its first order.
        return list(dict.fromkeys(extra_keywords)), list(dict.fromkeys(extra_regex))

    def run(self, apk_path: str, output_file: str = None, no_decompile: bool = False, rules: str = None):
        log.info(f"Starting analysis of {apk_path}...")

        # Reset per-run state before any LLM-backed pipeline stage. Resetting this after
        # summarization used to erase failures and could make an incomplete scan look clean.
        self.vulnerability_findings = []
        self.poc_results = []
        self.analysis_errors = []
        self._metrics_lock = threading.Lock()
        self.scan_metrics = {
            "decompiled_code_files": 0,
            "candidates_raw": 0,
            "candidates_scoped": 0,
            "summaries_requested": 0,
            "summaries_nonempty": 0,
            "summarization_calls": 0,
            "summary_batch_size": 1,
            "summary_batch_requests": 0,
            "summary_batch_items": 0,
            "summary_batch_valid_items": 0,
            "summary_batch_fallback_items": 0,
            "summary_batch_failures": 0,
            "risk_triage_calls": 0,
            "hybrid_risk_triage": "not_applicable",
            "app_summary_calls": 0,
            "attack_surface_calls": 0,
            "triage_yes": 0,
            "triage_no": 0,
            "triage_errors": 0,
            "static_pattern_hits": 0,
            "deep_scan_targets": 0,
            "deep_rule_checks": 0,
            "deep_rule_checks_scheduled": 0,
            "deep_rule_checks_accounted": 0,
            "deep_rule_checks_completed": 0,
            "deep_rule_checks_vulnerable": 0,
            "deep_rule_checks_not_vulnerable": 0,
            "deep_rule_checks_error": 0,
            "deep_rule_accounting_complete": True,
            "deep_scan_priority": "candidate_order",
            "deep_scan_files_scheduled": 0,
            "deep_scan_files_completed": 0,
            "deep_scan_files_error": 0,
            "deep_scan_file_accounting_complete": True,
            "manifest_rule_checks": 0,
            "strings_rule_checks": 0,
            "exploit_attempts": 0,
            "exploit_generated": 0,
            "exploit_successes": 0,
            "exploit_errors": 0,
            "exploit_validation_errors": 0,
            "candidate_collection_seconds": 0.0,
            "summarization_seconds": 0.0,
            "risk_triage_seconds": 0.0,
            "app_summary_seconds": 0.0,
            "attack_surface_seconds": 0.0,
            "deep_scan_seconds": 0.0,
        }
        
        active_rules = self._resolve_active_rules(rules)
        log.info(f"Active vulnerability rules: {len(active_rules)}")
        
        # XAPK/APKS preprocessing is additive to the existing APK path. Extraction uses
        # a fresh temp directory so a previous failed run cannot contribute a stale APK.
        original_input_path = apk_path
        archive_ext = os.path.splitext(apk_path)[1].lower()
        output_basename = os.path.basename(apk_path)
        bundle_extract_dir = None
        bundle_error = None
        if archive_ext in self.BUNDLE_EXTENSIONS:
            label = archive_ext.lstrip(".").upper()
            log.info(f"Detected {label} bundle: {apk_path}. Attempting safe extraction...")
            try:
                os.makedirs("output", exist_ok=True)
                bundle_extract_dir = tempfile.mkdtemp(prefix=f"dlh_{label.lower()}_", dir="output")
                self._safe_extract_bundle(apk_path, bundle_extract_dir)
                selected_apk = self._select_bundle_apk(bundle_extract_dir)
                if not selected_apk:
                    bundle_error = ("no_apk", f"No APK found inside {label} archive")
                else:
                    apk_path = selected_apk
                    selected_name = os.path.basename(selected_apk)
                    log.success(f"Extracted {label} and selected APK: {selected_apk}")
                    # Preserve the established XAPK output naming. APKS output remains
                    # tied to the archive because every split bundle tends to use the
                    # same inner filename (base-master.apk).
                    if archive_ext == ".xapk":
                        output_basename = selected_name
                    elif selected_name.lower() != "universal.apk":
                        # Scanning base-master is still useful and strictly additive, but
                        # feature splits are not silently declared analyzed.
                        self._record_pipeline_error(
                            original_input_path,
                            "bundle_selection",
                            "partial_split_scan",
                            "APKS has no universal.apk; scanning the selected base APK only. "
                            "Dynamic-feature splits remain unanalyzed.",
                        )
            except zipfile.BadZipFile as exc:
                bundle_error = ("invalid_archive", str(exc))
            except ValueError as exc:
                bundle_error = ("unsafe_archive", str(exc))
            except Exception as exc:
                bundle_error = ("exception", str(exc))

        self.apk_name = output_basename # Store for later use
        apk_name = self.apk_name
        output_dir = f"output/{apk_name}_decompiled"
        
        # [Moved from end] Calculate unique output file/dir options EARLY
        if output_file is None:
            base_filename = f"{output_basename}_results.json"
            base_exploit_dir_name = f"{os.path.splitext(output_basename)[0]}_exploits"
            
            # Initial candidates
            candidate_file = f"output/{base_filename}"
            candidate_exploit_dir = f"output/{base_exploit_dir_name}"
            
            # Versioning loop
            scan_count = 1
            while os.path.exists(candidate_file):
                 # Create suffix _scan1, _scan2...
                 candidate_file = f"output/{base_filename.replace('.json', '')}_scan{scan_count}.json"
                 candidate_exploit_dir = f"output/{base_exploit_dir_name}_scan{scan_count}"
                 scan_count += 1
            
            self.final_output_file = candidate_file
            self.final_exploit_dir = candidate_exploit_dir
        else:
            self.final_output_file = output_file
            filename_no_ext = os.path.splitext(os.path.basename(output_file))[0]
            self.final_exploit_dir = f"output/{filename_no_ext}_exploits"

        if bundle_error:
            reason, detail = bundle_error
            self._record_pipeline_error(original_input_path, "bundle_extraction", reason, detail)
            self._write_failed_scan_report()
            if bundle_extract_dir:
                shutil.rmtree(bundle_extract_dir, ignore_errors=True)
            return
        
        decomp_mode = self.settings.analysis.decompiler_mode
        log.info(f"Decompiler Mode: {decomp_mode}")

        if not no_decompile:
            # Apktool uses -f and clears its destination. Work in staging so Ctrl+C,
            # tool failure, or malformed input never destroys a previous good tree.
            staging_dir = f"{output_dir}.partial"
            shutil.rmtree(staging_dir, ignore_errors=True)
            os.makedirs(staging_dir, exist_ok=True)

            # 1. Always run Apktool (Need Manifest + Resources + Smali Fallback)
            log.info("Running Apktool...")
            try:
                decompiler = ApktoolHandler(apktool_path=self.settings.apktool.path or "apktool")
                decompiler.decompile(apk_path, staging_dir)
            except Exception as exc:
                reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
                self._record_pipeline_error(apk_path, "apktool_decompilation", reason, str(exc))
                shutil.rmtree(staging_dir, ignore_errors=True)
                self._write_failed_scan_report()
                if bundle_extract_dir:
                    shutil.rmtree(bundle_extract_dir, ignore_errors=True)
                return

            # 2. Run JADX if needed
            if decomp_mode in ["jadx", "hybrid"]:
                log.info("Running JADX...")
                try:
                    jadx_path = self.settings.jadx.path if self.settings.jadx else None
                    jadx = JadxHandler(jadx_path=jadx_path)
                    jadx_ok = jadx.decompile(apk_path, staging_dir)
                except Exception as exc:
                    jadx_ok = False
                    self._record_pipeline_error(
                        apk_path,
                        "jadx_decompilation",
                        "exception",
                        str(exc),
                    )
                if not jadx_ok:
                    # Apktool output is still available, so continue through the Smali
                    # fallback while making the partial JADX failure explicit.
                    if not any(
                        error.get("stage") == "jadx_decompilation" and error.get("file") == apk_path
                        for error in self.analysis_errors
                    ):
                        self._record_pipeline_error(apk_path, "jadx_decompilation", "no_sources")

            if not self._publish_decompile(staging_dir, output_dir, apk_path):
                self._record_pipeline_error(
                    apk_path,
                    "decompile_publication",
                    "incomplete_output",
                )
                self._write_failed_scan_report()
                if bundle_extract_dir:
                    shutil.rmtree(bundle_extract_dir, ignore_errors=True)
                return

        if bundle_extract_dir:
            shutil.rmtree(bundle_extract_dir, ignore_errors=True)
            bundle_extract_dir = None

        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            detail = self._describe_decompile_dir(output_dir)
            log.error(f"Cannot scan '{output_dir}': {detail}.")
            self._record_pipeline_error(
                output_dir,
                "decompile_validation",
                "missing_manifest",
                detail,
            )
            self._write_failed_scan_report()
            return

        try:
            self.scan_metrics["decompiled_code_files"] = sum(
                1
                for root, _, files in os.walk(output_dir)
                for filename in files
                if filename.endswith((".java", ".smali"))
            )
        except Exception as exc:
            self._record_pipeline_error(output_dir, "metrics", "file_count_error", str(exc), status="Error")

        # BUILD CALL GRAPH (Only supports Smali for now)
        if self.settings.analysis.use_cross_reference_context:
            try:
                self.call_graph_builder = CallGraphBuilder(output_dir)
                self.call_graph_builder.build()
            except Exception as exc:
                log.error(f"Call graph generation failed; continuing without dependency context: {exc}")
                self._record_pipeline_error(output_dir, "call_graph", "exception", str(exc))
                self.call_graph_builder = None
        else:
            self.call_graph_builder = None

        smali_rules_enabled = any(rule_name not in DEDICATED_PASS_RULES for rule_name in active_rules)

        self.summaries = {}
        target_files = [] # Files we will actually scan (either .smali or .java)
        # Dedicated strings analysis is independent of whether code rules find targets.
        try:
            strings_results = self.analyze_strings_xml(output_dir, active_rules)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            log.error(f"strings.xml analysis failed: {exc}")
            strings_results = [self._build_error_result(
                output_dir,
                "hardcoded_secrets_xml",
                "Hardcoded Secrets (strings.xml)",
                reason=reason,
                detail=str(exc),
            )]
        
        if smali_rules_enabled:
            filter_mode = self.settings.analysis.filter_mode
            log.info(f"Using filter mode: {filter_mode}")

            # --- DYNAMIC KEYWORD & REGEX GATHERING ---
            extra_keywords, extra_regex = self._load_rule_signals(active_rules)
            
            if extra_keywords:
                log.info(f"Loaded high-value keywords: {len(extra_keywords)}")
            if extra_regex:
                log.info(f"Loaded high-value regex patterns: {len(extra_regex)}")

            # --- SCOPE IDENTIFICATION ---
            # Parse Manifest early to get package name for filtering
            manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
            app_package_name = ""
            if os.path.exists(manifest_path):
                try:
                    parser = ManifestParser(manifest_path)
                    app_package_name = parser.package_name
                    self.manifest_parser = parser  # [B] reused by analyze_file for reachability context
                    log.info(f"Identified App Package: {app_package_name}")
                except Exception as e:
                    log.warning(f"Failed to parse package name: {e}")
                    self._record_pipeline_error(manifest_path, "manifest_parsing", "exception", str(e))

            # --- STRATEGY SELECTION ---
            
            # Set scan roots
            smali_dir = output_dir # Root of decompiled dir, CodeFilter walks this
            # JADX usually creates 'sources' inside output_dir
            java_dir = os.path.join(output_dir, "sources") 
            
            potential_targets = []
            candidate_collection_started = self._metric_timer_start()
            
            # A. STATIC FILTER PHASE
            if filter_mode in ["static_only", "hybrid"]:
                use_strict = (filter_mode == "hybrid")
                try:
                    potential_targets = self._collect_static_candidates(
                        decomp_mode,
                        smali_dir,
                        java_dir,
                        extra_keywords,
                        extra_regex,
                        use_strict,
                    )
                except Exception as exc:
                    self._metric_record_duration(
                        "candidate_collection_seconds", candidate_collection_started
                    )
                    log.error(f"Static candidate collection failed: {exc}")
                    self._record_pipeline_error(
                        output_dir,
                        "candidate_collection",
                        "exception",
                        str(exc),
                    )
                    self._write_failed_scan_report()
                    return

            # B. LLM_ONLY PHASE (Get everything)
            else: 
                # This is risky/expensive for JADX if huge source tree. 
                # But logic is "summarize everything".
                if decomp_mode == "apktool":
                     # Walk smali
                     for root, _, files in os.walk(smali_dir):
                        for file in files:
                            if file.endswith(".smali"): potential_targets.append(os.path.join(root, file))
                else: 
                     # Walk java
                     if os.path.exists(java_dir):
                        for root, _, files in os.walk(java_dir):
                            for file in files:
                                if file.endswith(".java"): potential_targets.append(os.path.join(root, file))

            self._metric_record_duration(
                "candidate_collection_seconds", candidate_collection_started
            )

            self.scan_metrics["candidates_raw"] = len(potential_targets)
            
            # --- SMART FALLBACK & SELECTION ---
            # Now we have 'potential_targets'. 
            # If we are in 'hybrid' DECOMPILER mode, we check content quality.
            
            final_targets_for_summary = []
            
            for target in potential_targets:
                if decomp_mode == "hybrid" and target.endswith(".java"):
                    # Check if valid
                    try:
                        if os.path.getsize(target) < 50: # Empty or just package decl
                             # Fallback
                             fallback = self._find_smali_fallback(target, output_dir)
                             if fallback:
                                 log.info(f"Smart Fallback: Switching {os.path.basename(target)} to Smali due to low quality.")
                                 final_targets_for_summary.append(fallback)
                             else:
                                 final_targets_for_summary.append(target) # Keep it if no fallback
                        else:
                             final_targets_for_summary.append(target)
                    except:
                        final_targets_for_summary.append(target)
                else:
                    final_targets_for_summary.append(target)

            # [V1.1.4] Apply Scope Filtering
            filtered_targets = []
            skipped_count = 0
            for target in final_targets_for_summary:
                if self._is_relevant_file(target, app_package_name):
                    filtered_targets.append(target)
                else:
                    skipped_count += 1
            
            if skipped_count > 0:
                log.info(f"Scope Filter: Ignored {skipped_count} library/irrelevant files.")
            
            final_targets_for_summary = filtered_targets
            self.scan_metrics["candidates_scoped"] = len(final_targets_for_summary)

            
            # --- SUMMARIZATION & RISK ID PHASE ---
            
            if filter_mode == "static_only":
                 target_files = final_targets_for_summary
                 # No summarization logic for pure static, just pass to analyze
                 
            elif filter_mode == "hybrid":
                # Static found targets -> Summarize them -> Ask LLM
                self.scan_metrics["hybrid_risk_triage"] = (
                    "legacy_enabled"
                    if self.settings.analysis.hybrid_risk_triage
                    else "skipped_redundant"
                )
                self.scan_metrics["deep_scan_priority"] = "static_pattern_then_scoped_stable"
                if final_targets_for_summary:
                    summarization_started = self._metric_timer_start()
                    self.summaries = self.summarize_chunks(
                        output_dir,
                        file_list=final_targets_for_summary,
                        summary_workers=self.settings.analysis.summary_workers,
                        summary_batch_size=getattr(
                            self.settings.analysis, "summary_batch_size", 1
                        ),
                    )
                    self.scan_metrics["summary_batch_size"] = getattr(
                        self.settings.analysis, "summary_batch_size", 1
                    )
                    self._metric_record_duration("summarization_seconds", summarization_started)
                    self.scan_metrics["summaries_requested"] = len(final_targets_for_summary)
                    self.scan_metrics["summaries_nonempty"] = sum(
                        1 for summary in self.summaries.values() if summary and summary.strip()
                    )
                    # A first-party file that matches a rule's detection_pattern is a strong
                    # static signal; deep-scan it even if the LLM risk-triage said "no" (it
                    # dropped a real hit — ZipSlipActivity — before any rule could run).
                    pattern_risky = self._pattern_matched_files(
                        final_targets_for_summary, extra_regex, app_package_name
                    )
                    if self.settings.analysis.hybrid_risk_triage:
                        risk_triage_started = self._metric_timer_start()
                        llm_risky = self.identify_risky_chunks(self.summaries)
                        self._metric_record_duration(
                            "risk_triage_seconds", risk_triage_started
                        )
                        target_files = self._select_deep_scan_targets(
                            final_targets_for_summary, llm_risky, pattern_risky
                        )
                    else:
                        llm_risky = []
                        # Static-pattern files are priority only. Appending the complete
                        # scoped list keeps membership exhaustive and stable-deduplicated.
                        target_files = self._select_deep_scan_targets(
                            final_targets_for_summary, [], pattern_risky
                        )
                    self.scan_metrics["static_pattern_hits"] = len(pattern_risky)
                    self.scan_metrics["deep_scan_targets"] = len(target_files)
                    if self.settings.analysis.hybrid_risk_triage:
                        log.info(
                            f"Deep-scan targets: {len(llm_risky)} via risk-triage + "
                            f"{len(pattern_risky)} scoped static-pattern hits = "
                            f"{len(target_files)} unique after fail-open candidate union."
                        )
                    else:
                        log.info(
                            "Hybrid risk-triage skipped as redundant; "
                            f"{len(pattern_risky)} static-pattern hits prioritized and all "
                            f"{len(target_files)} scoped candidates retained."
                        )
                else:
                    target_files = []

            else: # llm_only
                # We summarized EVERYTHING (expensive!). 
                summarization_started = self._metric_timer_start()
                self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                self._metric_record_duration("summarization_seconds", summarization_started)
                self.scan_metrics["summaries_requested"] = len(final_targets_for_summary)
                self.scan_metrics["summaries_nonempty"] = sum(
                    1 for summary in self.summaries.values() if summary and summary.strip()
                )
                risk_triage_started = self._metric_timer_start()
                llm_risky = self.identify_risky_chunks(self.summaries)
                self._metric_record_duration("risk_triage_seconds", risk_triage_started)
                target_files = self._select_deep_scan_targets(final_targets_for_summary, llm_risky)
                self.scan_metrics["deep_scan_targets"] = len(target_files)

        # Re-assign from the actual list after strategy selection. This is a passive
        # observation only and is never read back by candidate selection.
        self.scan_metrics["deep_scan_targets"] = len(target_files)

        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        
        # The app summary and the attack-surface map are independent report sections:
        # both read only the manifest and the already-computed summaries, and neither
        # feeds the other or candidate selection. Running them back to back put two full
        # LLM round-trips on the critical path for no reason (measured 38s + 5s), so they
        # are issued concurrently. Each still records its own duration.
        def _run_app_summary():
            started = self._metric_timer_start()
            try:
                return self.summarize_app(manifest_path, self.summaries)
            finally:
                self._metric_record_duration("app_summary_seconds", started)

        def _run_attack_surface():
            started = self._metric_timer_start()
            try:
                return self.generate_attack_surface_map(manifest_path, self.summaries)
            finally:
                self._metric_record_duration("attack_surface_seconds", started)

        attack_surface_map = None
        if self.settings.analysis.generate_attack_surface_map:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as report_pool:
                summary_future = report_pool.submit(_run_app_summary)
                surface_future = report_pool.submit(_run_attack_surface)
                app_summary = summary_future.result()
                attack_surface_map = surface_future.result()
        else:
            app_summary = _run_app_summary()

        # Analyze the manifest file
        try:
            all_results = self.analyze_manifest(manifest_path, active_rules)
        except Exception as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
            log.error(f"Manifest analysis failed: {exc}")
            all_results = [self._build_error_result(
                manifest_path,
                "__manifest_analysis__",
                "Manifest Analysis",
                reason=reason,
                detail=str(exc),
            )]
        if strings_results:
            all_results.extend(strings_results)

        if smali_rules_enabled and target_files:
            # Analyze the identified files (may be .smali or .java).
            # Context injection works for both: the call graph is Smali-based, but
            # get_dependencies()/path_to_class() normalize .java paths (sources/) to the
            # same class names, so JADX/hybrid Java files still receive dependency context.
            
            max_workers = max(1, self.settings.analysis.max_workers)  # [#6] Configurable parallelism
            log.info(f"Deep scanning with {max_workers} worker(s)...")
            deep_scan_started = self._metric_timer_start()
            self.scan_metrics["deep_scan_files_scheduled"] = len(target_files)
            ordered_priority_merge = filter_mode == "hybrid"
            outcomes = [None] * len(target_files)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # ThreadPoolExecutor starts work in submission order. target_files is already
                # stable priority order in hybrid mode, and every target is submitted: priority
                # never becomes a cutoff or membership gate.
                future_to_index = {
                    executor.submit(self.analyze_file, file_path, active_rules): index
                    for index, file_path in enumerate(target_files)
                }
                for future in track(concurrent.futures.as_completed(future_to_index), total=len(future_to_index), description="Deep scanning files...", console=console):
                    index = future_to_index[future]
                    file_path = target_files[index]
                    try:
                        results = future.result()
                        if ordered_priority_merge:
                            outcomes[index] = {"results": results, "error": None}
                        else:
                            # Preserve the established completion-order merge for
                            # static_only/llm_only. Phase 4 is hybrid-specific.
                            all_results.extend(results)
                        self._metric_add("deep_scan_files_completed")
                    except Exception as exc:
                        log.error(f"{file_path} generated an exception: {exc}")
                        if ordered_priority_merge:
                            outcomes[index] = {"results": [], "error": exc}
                        else:
                            reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
                            all_results.append(self._build_error_result(
                                file_path,
                                "__file_analysis__",
                                "File Analysis",
                                reason=reason,
                                detail=str(exc),
                            ))
                        self._metric_add("deep_scan_files_error")

            # Completion order is nondeterministic, but report order must not be. Merge each
            # file's result in the exact priority/submission order after every future finished.
            # This is intentionally hybrid-only so static_only/llm_only behavior is unchanged.
            if ordered_priority_merge:
                for index, file_path in enumerate(target_files):
                    outcome = outcomes[index]
                    if outcome is None:
                        outcome = {
                            "results": [],
                            "error": RuntimeError("deep-scan worker produced no outcome"),
                        }
                        self._metric_add("deep_scan_files_error")
                    if outcome["error"] is not None:
                        exc = outcome["error"]
                        reason = "timeout" if isinstance(exc, TimeoutError) else "exception"
                        all_results.append(self._build_error_result(
                            file_path,
                            "__file_analysis__",
                            "File Analysis",
                            reason=reason,
                            detail=str(exc),
                        ))
                    else:
                        all_results.extend(outcome["results"])

            files_scheduled = self.scan_metrics["deep_scan_files_scheduled"]
            files_accounted = (
                self.scan_metrics["deep_scan_files_completed"]
                + self.scan_metrics["deep_scan_files_error"]
            )
            self.scan_metrics["deep_scan_file_accounting_complete"] = (
                files_scheduled == files_accounted
            )
            self._metric_record_duration("deep_scan_seconds", deep_scan_started)

        self.scan_metrics["deep_rule_checks_scheduled"] = self.scan_metrics["deep_rule_checks"]
        self.scan_metrics["deep_rule_accounting_complete"] = (
            self.scan_metrics["deep_rule_checks_scheduled"]
            == self.scan_metrics["deep_rule_checks_accounted"]
        )
        if not self.scan_metrics["deep_scan_file_accounting_complete"]:
            self._record_pipeline_error(
                self.apk_name,
                "deep_scan_accounting",
                "incomplete_file_accounting",
                "Not every scheduled deep-scan file produced a completed or error outcome.",
            )
        if not self.scan_metrics["deep_rule_accounting_complete"]:
            self._record_pipeline_error(
                self.apk_name,
                "deep_scan_accounting",
                "incomplete_rule_accounting",
                "Not every started deep-rule LLM check produced a verdict or Error outcome.",
            )

        # [#E] Collapse overlapping same-file findings (info-preserving via 'also_detected_by').
        all_results = self._dedupe_findings(all_results)

        # [V1.1.3] Generate Chained Exploits (Phase 2)
        if self.settings.analysis.generate_exploit and self.vulnerability_findings:
            self._generate_chained_exploits()

        # Cache failures are non-fatal to analysis, but they must remain visible in
        # the report instead of existing only in debug logs.
        self._collect_cache_errors()
        self._finalize_scan_metrics(all_results)

        final_report = {
            "scan_status": "CompletedWithErrors" if self.analysis_errors else "Completed",
            "app_summary": app_summary,
            "attack_surface_map": attack_surface_map,
            "results": all_results,
            "poc_results": self.poc_results,
            # [FIX #2] Surface unanalyzed file/rule pairs so a failed scan can't be
            # mistaken for a clean one.
            "analysis_errors": self.analysis_errors,
            "scan_metrics": self.scan_metrics,
        }

        # Output the report to the pre-calculated path
        with open(self.final_output_file, "w") as f:
            import json
            json.dump(final_report, f, indent=2)
        log.success(f"Analysis complete. Results saved to {self.final_output_file}")

        # [FIX #2] Warn loudly when some files/rules could not be analyzed.
        if self.analysis_errors:
            log.warning(
                f"{len(self.analysis_errors)} file/rule check(s) could NOT be analyzed "
                f"or had pipeline errors. These are marked Error/Unanalyzed and must NOT be read as clean. "
                f"See 'analysis_errors' in the report."
            )

        # [#4] Report cache effectiveness. Merge in exploit_llm_client's own stats when it's
        # a separate client (different exploit_provider/exploit_model) so the count is complete.
        stats = self._combined_cache_stats()
        if stats["enabled"]:
            log.info(f"Response cache: {stats['hits']} hit(s), {stats['misses']} miss(es).")

    def _load_system_prompt(self) -> str:
        with open("config/prompts/system_prompt.txt", "r") as f:
            return f.read()

    def _load_summarize_prompt(self) -> str:
        with open("config/prompts/summarize_prompt.txt", "r") as f:
            return f.read()

    def _load_identify_risk_prompt(self) -> str:
        with open("config/prompts/identify_risk_prompt.txt", "r") as f:
            return f.read()

    def _load_app_summary_prompt(self) -> str:
        with open("config/prompts/app_summary_prompt.txt", "r") as f:
            return f.read()

    def _load_attack_surface_prompt(self) -> str:
        with open("config/prompts/attack_surface_prompt.txt", "r") as f:
            return f.read()
