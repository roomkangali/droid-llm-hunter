# ✨ Droid LLM Hunter - Features

→ [Back to README](../README.md)

---

## 🧠 Core Intelligence

- **🧠 Intelligent Analysis Engine:** Droid LLM Hunter goes beyond regex. It breaks down code into chunks, summarizes functionality, and understands context before flagging vulnerabilities, significantly reducing false positives compared to traditional tools.

- **⭐ Staged Prompt Architecture:** Uses specialized prompts for summarization, deep rule analysis, app context, attack-surface mapping, and exploit generation. Risk-triage is retained only as an optional legacy ordering mechanism; it is not a candidate gate. [Read the Docs](PROMPT-EXPLANATION.md)

- **📚 RAG with OWASP MASVS:** Findings are automatically enriched with the relevant **OWASP Mobile Application Security Verification Standard (MASVS)** ID (e.g., `MASVS-STORAGE-1`) for rules that have a MASVS mapping defined, making your reports audit-ready instantly.

- **✅ Testbed-Verified Detection:** Detection quality is protected by deterministic regression tests and an opt-in semantic Golden Test. The recorded `gpt-daybreak-blue-latest` audit retains the current-model floor of **22/25**, with three model-sensitive gaps documented rather than hidden by changing expected results.

---

## 🔍 Scanning Strategy

- **🔍 Hybrid Filter Modes:** Choose your strategy!
  - **`llm_only`:** Summarizes the complete scoped code set and deep-scans it exhaustively; highest cost.
  - **`static_only`:** Uses static signals for candidate discovery, skips preliminary summaries/triage, then sends candidates to deep rule analysis.
  - **`hybrid`:** Uses enabled-rule signals to discover candidates, builds summary/cross-reference context, prioritizes pattern hits, and deep-scans every scoped candidate.

- **🏗️ Hybrid Architecture:** A "Rule-Signal Discovery → Scope → Parallel Summary → Exhaustive Priority Queue → Rule LLM" pipeline. It reduces redundant calls without converting ranking into a cutoff. [Read the Docs](ARCHITECTURE_EXPLANATION.md)

- **🎯 Offensive Recall Contract:** In `hybrid` mode, **all scoped candidates** are submitted to deep scan. Static-pattern hits only move to the front of the queue. Summary failures, timeouts, and invalid responses are recorded as `Error/Unanalyzed` and do not remove candidates. [Read the Docs](ARCHITECTURE_EXPLANATION.md)

- **⚡ Bounded Hybrid Concurrency:** Candidate summaries run with configurable `summary_workers` while their original order is restored before global context is built. Final A/B testing reduced preliminary calls from `2N` to `N` and retained identical candidate/file-rule membership. Optional summary batching remains opt-in (`summary_batch_size: 1` by default).

- **🛡️ Smart Scope Protection:** The "Immune System" of the scanner. Automatically filters out library code (e.g., `androidx`, `google`, `r0.java`) using a combination of **Package Whitelisting** (via Manifest) and **Library Blocklisting**. [Read the Docs](EXPLOIT_GENERATOR.md#1-smart-scope-filtering-the-immune-system)

- **🕵️‍♂️ Library Hunter Mode (v1.1.7):** A specialized "Supply Chain" scanner that targets malicious behavior in third-party SDKs (`--scan-libraries`). It bypasses the scope protection to find backdoors, droppers (`DexClassLoader`), and spyware behavior in libraries, using Strict Regex Filtering to save tokens.

---

## 🕸️ Context Awareness

- **🕸️ Context-Aware Scanning:** Utilizes a **Call Graph** to understand file dependencies. Use CrossReference Context to let the AI know _who_ calls a function and with _what_ arguments. [Read the Docs](CROSS_REFERENCE_CONTEXT.md)

- **⚔️ Attack Surface Mapper:** Combines **Manifest Structure** (Exported components) with **Code Logic** (AI Summaries) to identify high-risk entry points (e.g., specific activities processing unvalidated URLs). [Read the Docs](ATTACK_SURFACE_MAPPER.md)

- **👑 Cross-Component Chaining:** The "Crown Jewel". Capability that enables the AI to "connect the dots" between different files. It uses a **Two-Pass Analysis** (Discovery → Global Context → Execution) to generate chained exploits (e.g., using a token found in File A to exploit File B). [Read the Docs](EXPLOIT_GENERATOR.md#2-cross-component-chaining-the-crown-jewel)

---

## ⚙️ Configuration & Flexibility

- **🛠️ Flexible Configuration:** A simple yet powerful configuration file (`config/settings.yaml`) allows for easy management of LLM providers, models, rules, and **Decompiler Settings** (Apktool/JADX).

- **🤖 Multi-Provider Support:** Run locally with **Ollama** (free & private) or scale up with **Gemini**, **Groq**, **OpenAI**, **Anthropic**, **OpenRouter**, **9Router** (a self-hosted, OpenAI-compatible router that fans out to many providers/models behind one endpoint), and **Codex CLI** (a locally installed agent binary — no API key needed, it reuses your existing `codex login`).

- **💾 Response Cache & Resume:** Every successful LLM response is cached (content-addressed by model + prompt + code). A scan interrupted by a crash or rate limit can reuse finished responses on re-run. Thread-safe counters, per-key request deduplication, and atomic cache publication support concurrent summaries. Configurable `summary_workers`, `max_workers`, input truncation, and output limits round out the controls. [Read the Docs](CONFIGURATION.md#performance--cost-controls)

---

## 💥 Output & Exploitation

- **📊 Structured Security Reports:** Get detailed JSON output containing severity, confidence scores, evidence snippets, and even an "Attack Surface Map" of the application.

- **🔎 Auditable Completion Metrics:** `scan_metrics` records candidate counts, summary/triage/deep calls, scheduled/completed/error work, stage durations, and cache hits/misses. Incomplete accounting produces a pipeline error instead of a clean report.

- **🧹 Clean, De-duplicated Findings:** Overlapping rules that flag the same file (e.g. the WebView trio) are collapsed into one primary finding with an `also_detected_by` list — no lost data, far less noise. Analysis failures are reported honestly as `Error` (never silently marked "clean").

- **💥 PoC Generation with Independent Verification Status:** Generates Bash, HTML, Python, or Frida JS artifacts for confirmed findings, then records syntax/provenance/type validation separately in `poc_results`. A failed PoC remains available for manual review and never removes its static finding. Runtime reproduction is never claimed or launched automatically; it requires an explicitly authorized emulator/device. [Read the Docs](EXPLOIT_GENERATOR.md)

- **📦 Bundle Support (XAPK / APKS):** Safely extracts `.xapk` and `.apks` archives into fresh temporary directories and prefers `universal.apk`, then the base APK. Decompilation is staged and only replaces a previous usable tree after Apktool produces both `AndroidManifest.xml` and `apktool.yml`. Split-only APKS files are scanned at the selected base APK but explicitly reported as partial (`CompletedWithErrors`) because dynamic-feature splits remain unanalyzed.
