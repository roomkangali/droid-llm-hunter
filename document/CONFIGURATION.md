# ⚙️ Droid LLM Hunter - Configuration Guide

→ [Back to README](../README.md)

---

## Configuration File

All settings are managed in `config/settings.yaml`. This file controls:
- LLM provider & model
- API keys
- Vulnerability rules (enable/disable)
- Filter mode & decompiler mode
- External tool paths (Apktool, JADX)

---

## Filter Mode (`filter_mode`)

Configure the analysis strategy to balance discovery breadth, context, elapsed time, and provider cost. The shipped `config/settings.yaml` currently selects `static_only` for a faster initial scan; select `hybrid` explicitly when exhaustive processing of the hybrid scoped candidate set and summary-based context are required.

### 1. `llm_only`

**Candidate source:** complete Java/Smali code tree, followed by normal scope filtering.

**How it works:**

1. All code files for the selected decompiler output are collected and scope-filtered.
2. Every scoped file is summarized by the LLM (`summarize_chunks`).
3. Risk identification supplies ordering information.
4. `_select_deep_scan_targets()` retains the complete scoped set, so every scoped file is submitted to deep rule analysis.

| | |
|--|--|
| ✅ **Pros** | Does not depend on static signals for initial code-file discovery; maximum scoped breadth |
| ❌ **Cons** | Most expensive and slowest; still model/rule dependent and cannot guarantee 100% accuracy |

---

### 2. `static_only`

**Candidate source:** local keyword/regex matching (`CodeFilter`).

**How it works:**

1. The scanner searches using built-in signals plus the union of active-rule keywords/regex.
2. Matching files pass through normal scope filtering and are scheduled for deep scan.
3. Preliminary LLM summarization/risk-triage is skipped; applicable rule verdicts are still produced by the LLM.

| | |
|--|--|
| ✅ **Pros** | Fast initial pass; zero provider calls for preliminary filtering |
| ❌ **Cons** | Less application-wide summary context; discovery depends on available static signals |

---

### 3. `hybrid` *(Recommended)*

**Candidate source:** enabled-rule static signals, followed by LLM context and exhaustive scheduling.

**How it works:**

1. **Discovery:** Collect the union of keywords/regex from enabled rules and apply scope filtering.
2. **Context:** Summarize every scoped candidate with bounded parallel workers, restoring stable order afterward.
3. **Priority:** Put static-pattern hits first, then append every remaining scoped candidate.
4. **Deep analysis:** Submit the entire queue. The report waits for every scheduled file and rule check.

> **Current recall contract:** risk-triage is disabled by default because it was redundant. Static hits affect priority only; all scoped hybrid candidates reach deep scan. Summary/worker failures are recorded as `Error/Unanalyzed` and fail open. See [Architecture](ARCHITECTURE_EXPLANATION.md).

| | |
|--|--|
| ✅ **Pros** | Summary/cross-reference context with no post-discovery score/top-N cutoff |
| ❌ **Cons** | Can remain slow on large APKs; candidate discovery is still limited by active-rule signals |

---

### Usage Recommendations

| Scenario | Recommended Mode |
|----------|-----------------|
| Maximum scoped code-file breadth, cost secondary | `llm_only` |
| Contextual offensive audit of rule-signal candidates | `hybrid` ✅ |
| Very large initial pass or constrained time/tokens | `static_only` |

---

## Decompiler Mode (`decompiler_mode`)

Droid LLM Hunter supports dual decompilation to balance reliability and analysis quality.

### 1. `apktool` *(Classic)*

- **Format:** Smali (Assembly).
- **Pros:** 100% Reliability, critical for Manifest analysis.
- **Cons:** Harder for LLM to understand logic, higher token usage.

### 2. `jadx` *(Modern)*

- **Format:** Java Source Code.
- **Pros:** Native code format, LLM understands it perfectly, logic is clear.
- **Cons:** May fail on some obfuscated apps.

### 3. `hybrid` *(Smart Fallback — Recommended)*

- **Format:** Java (Primary) + Smali (Fallback).
- **Logic:** The engine tries to use JADX output. If JADX fails or produces empty/corrupt code for a file, it automatically switches to the Smali version from Apktool.
- **Result:** Best of both worlds — Analysis quality of Java with the reliability of Smali.

---

## LLM Providers

Supported `llm.provider` values: `ollama`, `gemini`, `groq`, `openai`, `anthropic`, `openrouter`, `router9`, `codex`.

### 9Router (`router9`)

[9Router](https://github.com/9router/9router) is a **self-hosted, OpenAI-compatible LLM router**: one local endpoint that fans out to many providers/models via a provider-prefixed model name (e.g. `gc/gemini-2.5-pro` routes through to Gemini). Configure it like any other provider:

```yaml
llm:
  provider: router9
  router9_model: gc/gemini-2.5-pro
  router9_api_key: sk-...
  router9_base_url: http://localhost:20128/v1/chat/completions   # your self-hosted instance
```

- **`router9_base_url` is configurable** (unlike the other clients, which hit a fixed public URL) since 9Router is self-hosted — host/port vary per install.
- **Streaming quirk:** 9Router's `/v1/chat/completions` endpoint was observed to return a **Server-Sent Events (SSE) stream** (`Content-Type: text/event-stream`, `data: {...}` chunks) even for a plain, non-streaming request. It was *also* observed sending that same `text/event-stream` header while the body is actually a single complete `chat.completion` JSON object glued directly to a trailing `data: [DONE]` with **no separating newline** — a shape that a naive line-based SSE parser silently drops, making every call return empty content. The client (`modules/llm_client/router9.py`) therefore ignores the `Content-Type` header entirely and **sniffs the response body**: bodies starting with `data:` are parsed as SSE, anything else is parsed as one JSON object (tolerating the stray trailing `data: [DONE]`).
- **Reasoning models eat into `max_tokens`:** routing to a reasoning-capable model (e.g. `gemini-2.5-pro`) burns part of the `max_tokens` budget on hidden `reasoning_tokens` before any visible output is produced. A too-low `max_tokens` can silently truncate the answer (`finish_reason: "length"`) — this was confirmed live against a real 9Router instance during testing. If responses look cut off, raise `llm.max_tokens` (same guidance as OpenRouter's `kimi-k3`, which needs `8192`).

### Codex CLI (`codex`)

The only provider that is **not an HTTP API**. [Codex CLI](https://developers.openai.com/codex/cli) is a locally installed agent binary, so instead of calling an endpoint the client (`modules/llm_client/codex.py`) shells out to `codex exec` — its non-interactive mode — and reads the agent's final message back.

```yaml
llm:
  provider: codex
  codex_model: gpt-daybreak-blue-latest   # pin explicitly (see the cache caveat below)
  codex_cli_path: codex      # must be on PATH, or give an absolute path
  codex_timeout: 300         # seconds per call (agent turns are slower than a plain API call)
  codex_sandbox: read-only   # read-only | workspace-write | danger-full-access
  codex_reasoning_effort: medium   # none|low|medium|high|xhigh|max|ultra (model-dependent)
```

- **No API key.** There is deliberately no `codex_api_key` setting: auth is whatever the local install already uses. Run `codex login` once (ChatGPT account or API key) and DLH picks it up. Verify with `codex login status`.
- **Pin `codex_model` — don't leave it `null`.** `null` inherits the `model` from `~/.codex/config.toml`, which is convenient but has a **cache trap**: the response cache keys on the model name, and an unpinned Codex client falls back to the constant label `codex:default`. Change the model in your global Codex config and the cache key does *not* change, so DLH silently reuses answers produced by the **old** model. Pinning the model here makes a model switch invalidate the cache correctly, and keeps scans reproducible (which matters — recall is model-sensitive).
- **Which model?** `codex exec -m <slug>` accepts any model your Codex account can use. `gpt-daybreak-blue-latest` is the one Codex itself describes as *"for broad defensive cybersecurity work"*, making it the natural default for vulnerability analysis; the other listed models are general-purpose agentic coding models.
- **Reasoning effort is model-dependent.** Verified live against `gpt-daybreak-blue-latest`: `none`, `low`, `medium`, `high`, `xhigh`, `max`, and `ultra` are accepted, while `minimal` is rejected — despite `minimal` appearing in the API's own enum error message. Check `~/.codex/models_cache.json` (`supported_reasoning_levels`) for other models. In practice `low`/`none` produce shallow verdicts, while `medium` and above actually identify the tainted source; raise to `high`/`xhigh` for a final audit.
- **Changing the effort invalidates the cache (as it should).** `reasoning_effort` changes the answer but never appears in the prompt, so the Codex client reports it to the response cache via `cache_fingerprint()` and it forms part of the cache key. Before this was wired up, a run at `low` followed by a run at `xhigh` returned the cached `low` answer and never called the model at `xhigh` — silently giving shallower analysis than requested. Note the fingerprint is empty when `codex_reasoning_effort` is `null`, because the effective value then comes from `~/.codex/config.toml`, which DLH cannot see: another reason to pin it here.
- **Why `read-only` is the right sandbox.** The code being analyzed is already fully inlined in the prompt, so the agent has no reason to write anything. Raising this to `workspace-write` / `danger-full-access` lets a model-generated command modify your machine — don't, unless you have a specific reason.
- **Deterministic context.** Each call runs in a **fresh empty temp directory** (`--cd`). Codex is an *agent* and will explore its working directory if given one, so pointing it at an empty dir keeps analysis reproducible and stops unrelated local files from being pulled into the model context.
- **Output capture.** `codex exec` prints a banner, session id, the echoed prompt and a token-usage footer to stdout, so the client uses `--output-last-message` (which writes *only* the agent's final message) rather than scraping stdout. The prompt is piped on **stdin**, so large decompiled-code prompts can't hit the `ARG_MAX` argv limit.
- **`max_tokens` does not apply.** The Codex CLI manages its own output budget and exposes no per-call output-limit flag, so `llm.max_tokens` is accepted for interface parity but has no effect on this provider.
- **Concurrency is safe.** Each call gets its own temp dir and last-message file, so `analysis.max_workers > 1` runs parallel `codex exec` processes without racing (verified live with concurrent calls).

### Routing `--generate-exploit` to a different provider (`exploit_provider` / `exploit_model`)

Some models happily analyze code for vulnerabilities but refuse — or silently return empty output — when asked to write a working PoC/verification script, even with authorized-assessment framing in `exploit_prompt.txt`. This was confirmed live: a reasoning model routed through `router9` returned nothing for `intent_redirection`, while Anthropic's `claude-opus-4-6` produced a complete script for the identical finding.

Rather than switching your whole `provider` just for exploit generation, point ONLY that stage at a different (known-permissive) provider/model:

```yaml
llm:
  provider: router9              # used for scanning/analysis (summarize, risk-ID, rule verification, ...)
  router9_model: jem/glm-5.2
  anthropic_api_key: sk-ant-...   # already present for the `anthropic` provider — reused below, no duplication
  anthropic_model: claude-opus-4-6
  exploit_provider: anthropic     # --generate-exploit only: use Anthropic instead of router9
  # exploit_model: claude-sonnet-4-5-20250929   # optional: override the model on exploit_provider (or on `provider`, if exploit_provider is unset)
```

- **Both fields are optional and independent.** `exploit_provider` alone switches provider (using that provider's own default model). `exploit_model` alone keeps the same provider but overrides just the model. Neither set → exploit generation uses the main `provider`/model, unchanged from before this feature existed.
- **No separate API key field** — `exploit_provider: anthropic` reuses `anthropic_api_key`/`anthropic_model` already in this file; there's no `exploit_api_key`.
- **Safe by design:** the exploit-specific client is only built when `--generate-exploit` is actually requested, so a typo'd `exploit_provider` never breaks a normal scan. If building it fails for any reason, DLH logs a warning and falls back to the main provider/model rather than crashing the whole run.
- **Cache-friendly:** the response cache is keyed by model, so exploit-gen calls and scan calls never collide even when routed to different providers; the end-of-run `Response cache: N hit(s), M miss(es)` line reports the combined total.

## JADX Path Configuration

If `jadx` is not in your system PATH, specify the absolute path in `settings.yaml`:

```yaml
jadx:
  path: "/opt/jadx/bin/jadx"
```

---

## Performance & Cost Controls

These live under `analysis:` and `llm:` in `config/settings.yaml` and control speed, token cost, and resumability.

### Response Cache (`analysis.use_cache`) — default `true`

Every **successful** LLM response is cached on disk under `output/.dlh_cache/`, keyed by a hash of `model + system prompt + rule prompt + code`.

- **Resume:** if a scan crashes or exhausts your rate limit, just run the **same command again** — completed calls are reused for free, only the unfinished ones hit the LLM.
- **Dedup:** identical content analyzed twice costs a single call.

Failed (empty) responses are never cached, so they are retried on the next run. The cache is *content-addressed*: change the model, a rule prompt, or the APK and the affected entries recompute automatically — no manual clearing needed.

```bash
# Disable for one run (force fresh calls, no resume):
python dlh.py scan target.apk --no-cache

# Reset the cache entirely:
rm -rf output/.dlh_cache
```

At the end of a scan the log reports effectiveness, e.g. `Response cache: 40 hit(s), 2 miss(es).`

### Parallelism (`analysis.max_workers`) — default `2`

Number of files deep-scanned in parallel. Raise it for fast providers (Groq, Gemini); keep it low if you hit rate limits.

### Hybrid Summary Parallelism (`analysis.summary_workers`) — default `2`

Number of candidate files summarized concurrently in `hybrid` mode. The value is bounded to `1..32`; use `1` to restore serial summarization for a rate-limited provider. Every scoped candidate is still summarized and scheduled for deep scan, and results are restored to their original file order before cross-reference, app-summary, and attack-surface context is built. This setting does not change `static_only` or `llm_only` behavior.

### Optional Hybrid Summary Batching (`analysis.summary_batch_size`) — default `1`

Experimental opt-in batching for hybrid summaries, bounded to `1..32`. The default `1` preserves the established per-file/per-Smali-chunk prompt and cache identity. Values above `1` ask the provider for a strict opaque-ID-to-summary JSON mapping; a partial response retries only missing items individually, while an empty, invalid, or timed-out batch retries every affected item individually. If that fallback also fails, the file remains scheduled for deep scan and is reported `Unanalyzed`.

Partial or invalid batch responses are removed from cache, while valid individual fallbacks retain the original cache key. A trailing single item is always processed individually because wrapping it cannot save a call. Batch size `4` passed the recorded golden recall contract, but remains opt-in because total runtime depends on provider latency, prompt size, call graph, deep scan, and fallback rate.

### Hybrid Risk Triage (`analysis.hybrid_risk_triage`) — default `false`

The legacy risk-triage call only changed priority after hybrid was made exhaustive, so it is skipped by default. Static-pattern hits are processed first and every remaining scoped candidate still reaches deep analysis. Set this to `true` only to restore the legacy LLM-based ordering for A/B comparison or rollback; it adds one LLM call per successful file summary and does not increase candidate coverage.

Hybrid deep scanning submits this complete ordered target list to the bounded executor. Pattern hits start first, but the report waits for every target; there is no top-N, score threshold, time cutoff, or early stop. `scan_metrics` records scheduled/completed/error file tasks and scheduled/accounted deep-rule calls. An incomplete accounting state is reported as a pipeline error, never as a clean scan. This ordered result merge applies only to `hybrid`; `static_only` and `llm_only` retain their existing paths.

### Choosing a Profile for a Large APK

Use this conservative hybrid profile when preserving hybrid context and exhaustive analysis of every scoped candidate is the priority:

```yaml
analysis:
  filter_mode: hybrid
  summary_workers: 2
  summary_batch_size: 1
  hybrid_risk_triage: false
```

Increase `summary_workers` only within the provider's concurrency/rate limit. A rejected or unstable provider can create retries and erase the benefit; setting it back to `1` changes execution speed, not candidate membership. Batch size `4` is an optional high-latency-provider experiment with per-item fail-open fallback. It is not the default because measured end-to-end gains were not consistent.

For a very large first pass where elapsed time matters more than hybrid cross-reference summaries, select `filter_mode: static_only`. It skips hybrid summarization and risk-triage, but still sends the resulting static candidates through rule analysis; it is not equivalent to hybrid and may provide the agent less application-wide context. Follow with hybrid for the rules or attack surfaces that need deeper context.

An explicit `--rules` list is an operator-selected audit scope, not an automatic performance optimization. It intentionally excludes rules the operator did not request (and requested rules must be enabled in `settings.yaml`). Do not use a narrow list when the objective is a full vulnerability sweep.

These optimizations do not guarantee that a large APK finishes in under an hour. Candidate collection, full Smali call-graph construction when cross-reference is enabled, and exhaustive deep rule analysis still run. Cache hits avoid provider calls but do not skip that queue or convert an incomplete scan into a clean result.

### Input Truncation (`analysis.max_input_chars`) — default `30000`

Caps how much file content is sent to the LLM per call (keeps the head + tail, drops the middle with a `[TRUNCATED …]` marker). Prevents oversized files from blowing the context window or inflating cost. Set `0` to disable.

### Output Tokens (`llm.max_tokens`) — default `4096`

Maximum tokens the LLM may return per call. Raise it if long JSON findings or generated exploits get cut off (a truncated response causes JSON parse failures).

---

## Quick Config via CLI

```bash
# Set LLM provider
python dlh.py config provider gemini

# Set model
python dlh.py config model gemini-2.5-flash

# Set filter mode
python dlh.py config filter-mode hybrid

# Set decompiler mode
python dlh.py config decompiler-mode hybrid

# Show current configuration
python dlh.py config show

# Run interactive setup wizard
python dlh.py config wizard
```
