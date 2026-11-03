# Hybrid Architecture: Smart Engine Filtering + LLM Verification

→ [Back to FEATURES](FEATURES.md)

---

Hybrid mode combines rule-driven static discovery with LLM context and exhaustive deep scheduling. Its performance optimizations change execution order and remove redundant calls; they do not turn a score, risk vote, top-N list, or time budget into a candidate cutoff.

---

## The Previous Hybrid Bottleneck

The previous exhaustive hybrid path performed two preliminary LLM calls for each scoped candidate:

```text
N sequential summary calls
+ N sequential risk-triage calls
+ deep rule analysis
```

Risk-triage no longer controlled candidate membership because the selector already appended the complete candidate list. It consumed another `N` calls only to influence order, while sequential summarization prevented available provider concurrency from being used.

---

## Current Hybrid Pipeline

### Stage 1: Enabled-Rule Signal Discovery

`CodeFilter` collects files matching the **union** of keywords and regex patterns supplied by all active rules. Hybrid strict mode does not add the old catch-all keyword list, so active rules define the discovery surface. A file can enter through a keyword even when it does not match a regex.

The package-aware scope filter then removes known third-party/irrelevant paths. `--scan-libraries` is additive: its library-specific candidates are unioned with, rather than substituted for, the normal candidate set.

This is the candidate-discovery boundary. It is not a model score threshold, and the performance work did not narrow any existing rule keyword or regex.

### Stage 2: Parallel, Deterministic Summarization

Every scoped hybrid candidate is summarized. `analysis.summary_workers` bounds concurrent calls (`2` by default), while results are restored to original candidate order before app-summary, attack-surface, and cross-reference context are built.

Summary failure is fail-open:

```text
timeout / exception / empty / invalid batch item
        -> record Error/Unanalyzed
        -> retain candidate for deep scan
```

`summary_batch_size` remains `1` by default. Values above `1` are opt-in; partial or invalid batches retry affected items individually using their established context. A failed fallback never marks the candidate safe.

### Stage 3: Exhaustive Priority Queue

Files matching an enabled rule's `detection_pattern` are placed first. Every remaining scoped candidate is appended in stable order, deduplicated, and submitted to the bounded deep-scan executor.

```text
priority = static-pattern hits + every remaining scoped candidate
membership = every scoped candidate
```

The legacy `identify_risk_prompt.txt` path is disabled by default (`hybrid_risk_triage: false`) because it was redundant. Enabling it restores its ordering signal for comparison/rollback, but `_select_deep_scan_targets()` still unions the complete candidate list: a `NO`, timeout, or malformed triage response cannot remove a file.

### Stage 4: Deep Rule Analysis

Each scheduled file is evaluated against active rules. A rule's own `detection_pattern`/`static_analysis.patterns` routes that file-rule pair; rules without a pattern always run. A matched pair reaches the specialized rule LLM, which evaluates attacker control, sink use, validation, and exploitability.

All futures finish before hybrid results are merged in stable submission order. The report records scheduled/completed/error files and scheduled/accounted rule checks. Incomplete accounting becomes a pipeline error, never a clean scan.

### Stage 5: Specialized Resource Pipelines
Some rules target **configuration files** (XML) rather than source code. These bypass the Regex Filter and use dedicated parsers:

*   **Manifest Analysis:** 
    *   `strandhogg.yaml` (Task Hijacking via `taskAffinity`)
    *   `exported_components.yaml` (Exposed Activities/Receivers)
    *   `deeplink_hijack.yaml` (Missing `autoVerify` in Deep Links)
*   **Strings Analysis:** 
    *   `hardcoded_secrets_xml.yaml` (Secrets in `res/values/strings.xml`)
*   **Mechanism:** The Engine directly locates and analyzes these specific files if the rule is enabled, skipping the generic file scan.

---

## 💾 Cross-Cutting Layer: The Response Cache

Wrapping every LLM-backed stage is a content-addressed response cache. Before a request reaches the provider—summarization, optional legacy risk identification, deep-rule verification, app summary, attack-surface mapping, or exploit generation—the engine computes a hash from model/client fingerprint, prompts, and code and checks `output/.dlh_cache/`:

```text
        [ Any LLM call ]
              |
              v
     +------------------+     HIT     +--------------------------+
     |   CACHE CHECK    |------------>|  Return stored response  |
     |  (hash lookup)   |             |   (0 tokens, instant)    |
     +------------------+             +--------------------------+
              | MISS
              v
     +------------------+   success   +--------------------------+
     |  Call real LLM   |------------>|  Write response to cache |
     +------------------+             +--------------------------+
              | (empty / failed response -> NOT cached, retried later)
```

*   **HIT:** the stored response is returned instantly, at zero token cost.
*   **MISS:** the LLM is called, and only a **successful** response is written back. Failed (empty) responses are never cached, so a later run retries them.

This lets an interrupted scan reuse completed responses and deduplicates concurrent requests for the same key. Cache counters are synchronized and successful files are published atomically. A cache hit avoids provider work, but it does not bypass candidate scheduling or deep-scan accounting. Toggle via `analysis.use_cache` or `--no-cache`. See [Configuration](CONFIGURATION.md#performance--cost-controls).

---

## 🛠️ Technical Implementation

1.  **Engine (`code_filter.py` & `engine.py`):**
    *   Builds candidates from the additive union of active-rule keywords/regex.
    *   Runs summaries with bounded workers and restores deterministic context order.
    *   Uses static hits as priority only, then submits the complete scoped queue.
    *   Reconciles file and rule accounting before publishing a completed report.

2.  **Rules (`yaml`):**
    *   Vulnerability rules now support a new field: `detection_pattern`.
    *   Example from `pending_intent_hijacking.yaml`:
        ```yaml
        detection_pattern: "PendingIntent(?:\\.|;->)(getActivity|getService|getBroadcast).*(FLAG_MUTABLE|33554432)"
        ```

---

## Verified Effect

The final synthetic A/B profile retained `1,052/1,052` scoped/deep files and `315/315` file-rule checks. Removing redundant triage reduced total calls from `2,421` to `1,369` (43.45%), while two summary workers reduced summary time by 49.44%. End-to-end synthetic orchestration improved by 9.44%.

Those numbers use a deterministic fake provider and are not a promise about real Codex latency. Large APKs can still take hours because Smali call-graph construction, candidate collection, and exhaustive deep rule analysis remain. The golden current-model audit retained 22/25 recall with no new precision violation or hidden analysis error.

---

## ❓ FAQ: Backward Compatibility

### Will keyword-only rules still run?

Yes. Keywords and regex patterns are additive during candidate discovery. At deep analysis, a rule without `detection_pattern` or `static_analysis.patterns` is treated as a logic rule and runs without a pattern cutoff.

### Does adding a `detection_pattern` switch the global mode?

No. `filter_mode` is selected explicitly in `settings.yaml` or through `config filter-mode`. A rule pattern contributes discovery/routing signals inside `hybrid` or `static_only`; it does not change the global mode.

## ⚠️ Limitations & Trade-offs (Blind Spots)

For full transparency, rule-driven candidate discovery can miss unfamiliar wrappers, obfuscated identifiers, reflection, or APIs not represented by current additive signals. No universal coverage percentage is claimed.

### 1. Hardcoded Secrets (Entropy + Naming)
*   **Pattern:** `(?i)(AIza…|AKIA…|const-string.*(api_key|password|secret|token)|(api_key|password|secret|token).*=.*["'])`
*   **Strength:** Catches BOTH high-entropy key prefixes (Google `AIza…`, AWS `AKIA…`) *regardless of the variable name*, AND secret-looking variable assignments. (So `String x = "AIza…";` **is** caught via the prefix.)
*   **Weakness:** A secret with no known prefix stored under a random variable name (e.g. `String x = "9f3c…";`) can still be missed.
*   **Trade-off:** Flagging *every* string assignment would explode false positives and token cost. This is a necessary balance.

### 2. SQL Injection (Standard API Dependency)
*   **Pattern:** `(rawQuery|execSQL)\\s*\\(`
*   **Strength:** Catches the use of standard Android SQLite APIs.
*   **Weakness:** If using obscure 3rd-party ORMs or custom wrapper functions (e.g., `myDatabaseHelper.doQuery(...)`), it might be missed.
*   **Trade-off:** `rawQuery` accounts for the vast majority of SQLi vulnerabilities in native Android.

### 3. Insecure File Permissions (Constant + API Dependency)
*   **Pattern (v1.3.0):** `MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|set(Readable|Writable)\s*\(\s*true\s*,\s*false`
*   **Improvement (v1.3.0):** now also detects `File.setReadable(true, false)` / `setWritable(true, false)` — a real-world world-accessible pattern the old `MODE_WORLD_*`-only regex missed (VulnerAppDLH used exactly this, so the earlier "negligible" assumption was wrong).
*   **Remaining weakness:** the raw integer mode (`openFileOutput(f, 1)`) is still not flagged — matching a bare `1` would cause massive false positives. This narrow gap is accepted.

**Conclusion:** The current configuration represents the "Best Practice" sweet spot. Tightening regex increases False Negatives; loosening it explodes Token Costs.

> **v1.3.0 pattern refinements** (validated by the semantic Golden Test so recall did not regress): `path_traversal` now keys on the real read signal `(openFile|FileInputStream|FileOutputStream)\s*\(` instead of a bare `openFile` (which only matched by coincidence); `insecure_file_permissions` gained `setReadable/setWritable(true,false)`; and `universal_logic_flaw` was made **LLM-exclusive** (no `detection_pattern`) so per-rule gating never skips a conceptual flaw. Several method-call patterns are now dual-language (Java `.method` + Smali `;->method`).
