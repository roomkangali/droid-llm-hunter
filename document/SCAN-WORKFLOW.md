# 🔄 Droid LLM Hunter - Scan Workflow

→ [Back to README](../README.md)

---

## Overview

Droid LLM Hunter uses a multi-stage process to analyze an APK:

1.  **Decompilation:** The APK is decompiled using **Apktool** (for Smali/Manifest) and optionally **JADX** (for Java Source), depending on the `decompiler_mode`.
2.  **Candidate Discovery:** `static_only` and `hybrid` collect the union of enabled-rule keyword/regex signals; `llm_only` starts from the complete code tree.
3.  **Smart Scope Protection:** Irrelevant/library paths are removed using package context and blocklists. `--scan-libraries` additively restores library-hunting candidates.
4.  **Context Preparation:** Hybrid summarizes every scoped candidate with bounded workers, then restores stable order for cross-reference/app context. Summary failures are recorded and fail open.
5.  **Exhaustive Scheduling:** Hybrid prioritizes static-pattern hits, appends every remaining scoped candidate, and submits the full queue. Optional legacy risk-triage can affect ordering only; it cannot remove candidates.
6.  **Deep Rule Analysis:** Applicable active rule/file pairs are analyzed by the LLM. Every started check must produce a verdict or an `Error/Unanalyzed` record.
7.  **Global Context Building:** Findings and application context are assembled for reporting/exploit generation.
8.  **Chained Exploit Generation:** If explicitly enabled, PoCs use the Global Context to connect vulnerabilities across files. PoC validation status never deletes the underlying finding.
9.  **Enrichment & Reporting:** Findings are mapped to **OWASP MASVS**, all scheduled work is reconciled, and the JSON report is generated.

> **💾 Response Cache (cross-cutting):** Every LLM call in the stages above—summarization, optional legacy risk identification, deep-rule verification, app summary, attack-surface mapping, and exploit generation—passes through a content-addressed cache first. A hit avoids a provider call but does not remove the candidate from scheduling/accounting. See [Configuration](CONFIGURATION.md#response-cache-analysisuse_cache).

---

## Pipeline Diagram

```text
+-------------------------------------------------------+
|  PHASE 1: PREPARATION                                 |
|  [ Start ] -> [ Load Config ] -> [ Decompiler Engine ]|
|                      |             (Apktool / JADX)   |
|                      v                                |
|             [ Parse AndroidManifest.xml ]             |
|          (Extract Package Name & Components)          |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 2: SMART SCOPE PROTECTION (The Immune System)  |
|                                                       |
|  [ All Smali/Java Files ]                             |
|          |                                            |
|          v                                            |
|  [ SCOPE FILTER ]                                     |
|     1. Whitelist: Must match App Package Name         |
|     2. Blocklist: Drop known libs (androidx, r0...)   |
|          |                                            |
|          v                                            |
|  [ Relevant Files Only ] (Libraries Discarded)        |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 3: DISCOVERY & RISK ID (Hybrid Pass)           |
|                                                       |
|    [ Loop: Analyze Relevant Files ]                   |
|                 |                                     |
|                 v                                     |
|    [ REGEX FILTER (Zero Cost) ]                       |
|    (Match 'detection_pattern'?)                       |
|       NO |             | YES                          |
|          v             v                              |
|       [ Skip ]   [ CACHE CHECK ] --HIT--> [ Reuse ]   |
|                        | MISS                         |
|                        v                              |
|                  [ LLM VERIFICATION ]                 |
|                  (Context & Logic Check)              |
|                                |                      |
|                                v                      |
|                     [ Validate Finding ]              |
|                                |                      |
|                                v                      |
|                     [ Store in Knowledge Base ]       |
|                   (Do NOT Generate Exploits Yet)      |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 4: INTELLIGENT CHAINING (Pass 2)               |
|                                                       |
|      [ Build Global Context ]                         |
|   (Summarize all findings from Phase 3)               |
|                 |                                     |
|                 v                                     |
|    [ Loop: Generate Exploits ]                        |
|                 |                                     |
|                 v                                     |
|      [ Inject Context + Manifest + Secrets ]          |
|   "Use the token from File A to hack File B"          |
|                 |                                     |
|                 v                                     |
|      [ Generate Chained Exploit Scripts ]             |
|       (Python / Bash / HTML / Frida)                  |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 5: REPORTING                                   |
|                                                       |
|      [ JSON Report ] + [ Exploit Artifacts ]          |
+-------------------------------------------------------+
```

---

## JSON Report Structure

The report is a JSON object with:
- **`app_summary`** — executive summary of the app's capabilities.
- **`attack_surface_map`** — entry-point map (only if `generate_attack_surface_map` is enabled).
- **`results`** — a list of findings. Each has `file`, `rule`, `vulnerability` (name), `status`
  (`Vulnerable` / `Not Vulnerable` / `Error`), and a structured `result` (severity, confidence,
  evidence, description, attack_scenario, recommendation, MASVS reference, …).
  - **[v1.3.0] `also_detected_by`** — when several overlapping rules flag the SAME file (e.g. the
    WebView trio, or the broad `universal_logic_flaw`), they are collapsed into one primary finding
    and the rest are listed here — nothing is lost, the report is just less noisy.
- **[v1.2.0] `analysis_errors`** — file/rule checks that could NOT be analyzed (empty or unparseable
  LLM response). These are `status: "Error"` and must be treated as **unanalyzed, not clean**.

For example reports, see the [output/](../output/) directory.
