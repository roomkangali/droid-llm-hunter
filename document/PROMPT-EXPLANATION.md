# Droid LLM Hunter - Prompt Architecture Documentation

→ [Back to FEATURES](FEATURES.md)

---

This document provides a detailed explanation of the role of each prompt file within the Droid LLM Hunter architecture, specifically after the implementation of OWASP MASVS Context Injection.

These prompts act as the "Brain" of the tool, guiding the AI through various stages of analysis.

---

### 1. `system_prompt.txt` (The Core Persona)
**Location:** `config/prompts/system_prompt.txt`
**Function:** 
Defines the core "Identity" of the AI. This file sets the standards and rules that the AI must follow in **every** request (especially during the vulnerability scanning phase).
**Key Roles:**
*   Establishes the role as a "World-Class Android Security Tester".
*   Enforces output in valid JSON format.
*   Mandates analysis based on **OWASP MASVS** principles.
*   Serves as the entry point for "Context Injection" (where specific MASVS rule definitions are dynamically injected by the Engine at runtime).
*   **[v1.3.0]** The Engine also appends a strict `JSON_ONLY_SUFFIX` after every rule prompt as the *final* instruction — reinforcing "JSON object only, no prose/markdown" to override any prose-inviting wording. Non-empty-but-unparseable replies are marked `status: "Error"`, never silently treated as clean.

### 2. `summarize_prompt.txt` (Phase 1: The Signal Seeker)
**Location:** `config/prompts/summarize_prompt.txt`
**Function:** 
Used during the `llm_only` or `hybrid` filtering phase. Its task is to condense thousands of lines of raw code into concise summaries focused on security features.
**Key Roles:**
*   Reads raw code chunks (Java/Smali).
*   **[NEW]** Explicitly instructed to look for sensitive categories (MASVS-AUTH, MASVS-CRYPTO, MASVS-NETWORK, etc.).
*   **Output:** Descriptive summaries containing "Tags/Signals" for the next phase.

### 3. `identify_risk_prompt.txt` (Optional Legacy Priority Classifier)
**Location:** `config/prompts/identify_risk_prompt.txt`
**Function:** 
Reads summaries and returns a coarse `YES`/`NO` risk vote. In the current hybrid default (`hybrid_risk_triage: false`) this call is skipped because exhaustive selection already sends every scoped candidate to deep scan.
**Key Roles:**
*   Matches "Tags/Signals" from the summary against a Trigger List.
*   If the summary contains MASVS keywords -> Risk = **YES**.
*   If the summary only contains common UI/Utility code -> Risk = **NO**.
*   **Ordering only:** when explicitly re-enabled for A/B or rollback, `YES` files may be prioritized, but `NO`, empty, timeout, or malformed responses cannot remove a candidate. `_select_deep_scan_targets()` always appends the full scoped candidate list.
*   A triage failure is recorded rather than interpreted as safe.

### 4. `app_summary_prompt.txt` (Reporting: The Big Picture)
**Location:** `config/prompts/app_summary_prompt.txt`
**Function:** 
Used at the end of the scan process to generate the opening paragraph of the final report (Executive Summary). This field is **report-only** — it is not re-injected as context into any other prompt.
**Key Roles:**
*   Reads `AndroidManifest.xml` (Permissions, Activities).
*   Reads code summaries found during analysis.
*   Generates an application description focusing on: Core Functionality, Security Features, Data Handling, and Dangerous Permissions.
*   **[v1.3.0]** Rewritten for information density: a ~120-180 word bullet-point summary, not a comprehensive essay. Prioritizes the **exported attack surface** (the most report-relevant section), states dangerous permissions actually present instead of enumerating absent ones, and forbids markdown tables/headers and closing disclaimers. Cut real-world output from ~1000-1600 tokens to ~360 tokens with no loss of security-relevant content (verified live against VulnerAppDLHv2).

### 5. `attack_surface_prompt.txt` (Reporting: The Map Maker)
**Location:** `config/prompts/attack_surface_prompt.txt`
**Function:** 
Used if the `generate_attack_surface_map` option is enabled. Its task is to map out entry points for attackers.
**Key Roles:**
*   Analyzes components where `exported=true` (Activity, Receiver, Service).
*   Identifies Deep Link URLs that can be triggered externally.
*   **Output:** a compact **structured JSON inventory** (`report["attack_surface_map"]`), not a narrative report.
*   **[v1.3.0]** Rewritten from a free-text "generate an attack surface map" essay to a strict JSON-inventory spec: `exported_activities`/`exported_receivers`/`exported_services`/`exported_providers` (short class names), `deep_links` (scheme/host/handler triples), `unprotected_broadcasts`, `network`/`file_io`/`ipc`/`deserialization`/`reflection` signals, and `manifest_flags`. No prose, no per-item impact commentary (that's already covered by the per-file vulnerability findings). `Engine.generate_attack_surface_map` now parses the response into a real dict (reusing `_parse_llm_response`) instead of storing raw LLM text; on failure it returns `{"error": ...}` instead of silently returning nothing. Cut real-world output from ~16,000 chars (~4000 tokens) of markdown to ~900 chars (~230 tokens) on VulnerAppDLHv2, with no loss of the underlying facts — a downstream report renderer (e.g. an HTML dashboard) is expected to turn this data into bullets/tables itself.

### 6. `vuln_rules/*.yaml` (Phase 3: The Detectors)
**Location:** `config/prompts/vuln_rules/*.yaml`
**Function:**
One file per vulnerability rule. Each supplies the `prompt` shown to the LLM during Deep Analysis, plus optional `detection_pattern` (regex), `static_analysis.patterns`, and `keywords` used for candidate discovery and file-rule routing.
**Key Roles:**
*   **[v1.3.0] Consistent template:** every rule follows *Vulnerability pattern → Tainted source → "not a finding if…"*, so the model reasons about attacker-controllability, not just keyword presence.
*   **[v1.3.0] Language-agnostic:** prompts say "decompiled Android code (Java or Smali)" with a neutral ```` ``` ```` code fence — no per-file `smali→java` string patching anymore.
*   **Per-rule routing:** in `hybrid`/`static_only` modes a rule's LLM call is skipped when none of that rule's patterns match the file. Pattern-less logic rules (for example `universal_logic_flaw`) always run on every scheduled candidate. Invalid regex fails open and runs the LLM.
*   **Manifest rules** (`exported_components`, `intent_spoofing`, `deeplink_hijack`, `webview_deeplink`, `strandhogg`) run only against `AndroidManifest.xml`, never the code scan (single-source `MANIFEST_RULES`).
*   **[v1.3.0] 26 toggleable rules** (A–Z in `RulesSettings`), including the new `intent_redirection` (confused-deputy IPC). A separate `library_vulnerability` supply-chain detector runs only under `--scan-libraries`.
*   **Output:** the structured JSON defined by the system prompt; overlapping findings on the same file are later collapsed via report de-duplication (`also_detected_by`).

---

### Prompt Execution Pipeline

The following diagram illustrates how these prompts interact sequentially during a single scan:

```text
[ START SCAN ]
      |
      v
[ PHASE 1: CANDIDATE DISCOVERY + SCOPE ]
Hybrid/static: enabled-rule keyword OR regex
LLM-only: complete code tree
      |
      v
[ PHASE 2: SUMMARIZATION ]
(Hybrid/LLM-only; hybrid uses bounded workers)
Prompt: `summarize_prompt.txt`
Input : "Raw Code (Java/Smali)"
Output: "Summary + MASVS Tags"
      |
      v
[ OPTIONAL LEGACY RISK PRIORITY ]
(Skipped by default in hybrid; never decides membership)
Prompt: `identify_risk_prompt.txt`
Input : "Summary + MASVS Tags"
Output: "YES" / "NO" ordering signal
      |
      v
[ PHASE 3: DEEP ANALYSIS (Vulnerability Scan) ]
(Every scoped hybrid candidate; static hits first)
Prompt: `system_prompt.txt` (Persona + MASVS Definition) + `vuln_rules/*.yaml`
Input : "Raw Code" + "Context"
Output: JSON verdict or Error/Unanalyzed
      |
      v
[ PHASE 4: REPORTING ]
(After all scans complete)
Prompt: `app_summary_prompt.txt`
Input : "AndroidManifest.xml" + "All Summaries"
Output: Application Description

Prompt: `attack_surface_prompt.txt` (Optional)
Input : "AndroidManifest.xml" + exported components
Output: Attack Surface Map
```

## Why Multiple Prompts Instead of One Prompt ?

Using a single monolithic prompt leads to:
- Higher token cost
- Poor reasoning consistency
- Increased hallucination risk

Droid LLM Hunter adopts a staged prompt architecture to:
- Isolate reasoning tasks
- Enforce decision boundaries
- Improve reproducibility and auditability
