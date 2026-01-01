# Droid LLM Hunter

**Droid LLM Hunter** is an automated security analysis tool designed to detect vulnerabilities in Android applications with high precision. By combining traditional static analysis (SAST) with the contextual understanding of **Large Language Models (LLMs)**, it bridges the gap between keyword-based scanning and human-like code review.

It supports **Hybrid Decompilation** (Smali/Java), **Context-Aware Analysis** (Call Graphs), and **Intelligent Risk Filtering**, ensuring that security engineers can focus on verified, high-severity findings rather than false positives.

<p align="center">
  <img src="logo/dlh-logo.png" width="1000">
</p>

<div align="center">

# 📦 Package Attributes

<p>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-yellow.svg" alt="Python Version"></a>
    <a href="https://github.com/roomkangali/dursgo/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
    <img src="https://img.shields.io/badge/AI-Powered-blue.svg" alt="AI Powered">
</p>
<p>
    <img src="https://img.shields.io/badge/Linux-Supported-green.svg" alt="Linux Supported">
    <img src="https://img.shields.io/badge/macOS-Supported-green.svg" alt="macOS Supported">
    <img src="https://img.shields.io/badge/Windows-Supported-green.svg" alt="Windows Supported">
</p>

</div>

---

  <div align="center">

### 🎬 Demo - Droid LLM Hunter

  </div>
  
  <table>
    <tr>
      <td align="center" valign="top">
        <strong>WebView via DeepLink - Exported Components</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=VBNsb8ibK9Q" target="_blank">
          <img src="https://img.youtube.com/vi/VBNsb8ibK9Q/hqdefault.jpg" alt="Demo 1" width="100%"/>
        </a>
      </td>
      <td align="center" valign="top">
        <strong>Hardcoded Secrets</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=F9sDP9qO1o0" target="_blank">
          <img src="https://img.youtube.com/vi/F9sDP9qO1o0/hqdefault.jpg" alt="Demo 2" width="100%"/>
        </a>
      </td>
    </tr>
  </table>
</div>

---
## 📋 Table of Contents

- [✨ Features](#features)
- [⚙️ Scan Workflow](#scan-workflow)
- [💻 Available Scanners](#available-scanners)
- [🛡️ Available Rules](#available-rules)
- [🚀 Filter Mode Scanners](#filter-mode-scanners)
- [🧩 Decompiler Modes](#decompiler-modes)
- [🔩 Installation](#installation)
- [📝 Configuration](#configuration)
- [💡 Usage](#usage)
  - [Examples](#examples)
  - [Flags](#flags)
  - [Commands](#commands)
- [🗺️ Development Roadmap](#development-roadmap)
- [❓ FAQ](#faq)
- [🙏 Contributing](#contributing)

## Features

*   **🧠 Intelligent Analysis Engine:** Droid LLM Hunter goes beyond regex. It breaks down code into chunks, summarizes functionality, and understands context before flagging vulnerabilities, significantly reducing false positives compared to traditional tools.
*   **⭐ Staged Prompt Architecture:** Uses a specialized pipeline of prompts (Summarization -> Filtering -> Deep Scan) to ensure consistent reasoning and reduce hallucination. [Read the Docs](Prompt-Explanation.md)
*   **🔍 Hybrid Filter Modes:** Choose your strategy!
    *   **`llm_only`:** Maximum accuracy using pure AI analysis.
    *   **`static_only`:** Blazing fast keyword scanning.
    *   **`hybrid`:** The best of both worlds—Static keywords filter the noise, AI verifies the danger.
*   **🛠️ Flexible Configuration:** a simple yet powerful configuration file (`config/settings.yaml`) allows for easy management of LLM providers, models, rules, and **Decompiler Settings** (Apktool/JADX).
*   **🕸️ Context-Aware Scanning:** Utilizes a **Call Graph** to understand file dependencies. Use Cross-Reference Context to let the AI know *who* calls a function and with *what* arguments. [Read the Docs](CROSS_REFERENCE_CONTEXT.md)
*   **📚 RAG with OWASP MASVS:** Every finding is automatically enriched with the relevant **OWASP Mobile Application Security Verification Standard (MASVS)** ID (e.g., `MASVS-STORAGE-1`), making your reports audit-ready instantly.
*   **🤖 Multi-Provider Support:** Run locally with **Ollama** (free & private) or scale up with **Gemini**, **Groq**, and **OpenAI**.
*   **📊 Structured Security Reports:** Get detailed JSON output containing severity, confidence scores, evidence snippets, and even an "Attack Surface Map" of the application.

## Scan Workflow

Droid LLM Hunter uses a multi-stage process to analyze an APK:

1.  **Decompilation:** The APK is decompiled using **Apktool** (for Smali/Manifest) and optionally **JADX** (for Java Source), depending on the `decompiler_mode`.
2.  **Smart Filtering:** Based on the `filter_mode`, the engine identifies potentially risky files using Static Analysis (`static_only`), AI Summarization (`llm_only`), or both (`hybrid`).
3.  **Risk Identification:** High-level analysis determines which files require deep inspection, discarding safe code to save time and tokens.
4.  **Deep Dive Analysis:** Only the "Risky" files are sent for full, context-aware vulnerability analysis using the enabled rules and Call Graph data.
5.  **Enrichment & Reporting:** Vulnerabilities are mapped to **OWASP MASVS** standards, and a detailed JSON report is generated.


```text
+-------------------------------------------------------+
|  PHASE 1: PREPARATION                                 |
|  [ Start ] -> [ Load Config ] -> [ Decompiler Engine ]|
|                      |             (Apktool / JADX)   |
|                      v                                |
|                      v                                |
|             [ Build Call Graph ]                      |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 2: FILTERING & RISK ID (The Funnel)            |
|                                                       |
|  [ All Smali Files ]                                  |
|          |                                            |
|          v                                            |
|  [ FILTER STRATEGY (Static / LLM / Hybrid) ]          |
|          |                                            |
|          v                                            |
|  [ Identify Risky Files ] -> (Discard Safe Files)     |
|          |                                            |
|      (List of Risky Files)                            |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 3: INTELLIGENT DEEP ANALYSIS                   |
|                                                       |
|    [ Loop: Iterate Risky Files Only ] <-----------+   |
|                 |                                 |   |
|                 v                                 |   |
|      [ Context Injection Engine ]                 |   |
|   (Inject Dependencies & Call Graph)              |   |
|                 |                                 |   |
|                 v                                 |   |
|      [ LLM Inference (Deep Scan) ]                |   |
|   ("Is this specific vulnerability present?")     |   |
|                 |                                 |   |
|                 v                                 |   |
|         [ Store Findings ] -----------------------+   |
+----------------------+--------------------------------+
                       |
                       v
+----------------------+--------------------------------+
|  PHASE 4: ENRICHMENT & REPORTING                      |
|                                                       |
|      [ Map Findings to OWASP MASVS ]                  |
|                 |                                     |
|                 v                                     |
|      [ Generate JSON Report ]                         |
+-------------------------------------------------------+
```

**For more detailed** information **JSON Report** Structure, see the [JSON Report](output/)

## Available Scanners

Droid LLM Hunter supports the following LLM providers:

*   **Ollama:** For running local LLMs. (Recommended)
*   **Gemini:** Google's family of generative AI models.
*   **Groq:** A high-performance inference engine for LLMs.
*   **OpenAI:** OpenAI's family of generative AI models.

## Available Rules

Rules Vulnerability Droid LLM Hunter:

Enable or Disable these rules in `config/settings.yaml`:
- `true`: Enable the rule.
- `false`: Disable the rule.


```bash
- sql_injection
- webview_xss
- hardcoded_secrets
- webview_deeplink
- insecure_file_permissions
- intent_spoofing
- insecure_random_number_generation
- jetpack_compose_security
- biometric_bypass
- graphql_injection
- exported_components
- deeplink_hijack
- insecure_storage
- path_traversal
- insecure_webview
```

## Filter Mode Scanners

Configure the analysis strategy using `filter_mode` in `settings.yaml` to balance speed, cost, and accuracy.

### 1. `llm_only` (Default)
**Decision Maker:** 100% AI (LLM).

**How it works:**
1. All Smali files are chunked and summarized by the LLM (`summarize_chunks`).
2. The summaries are analyzed by the LLM to identify risks (`identify_risky_chunks`).
3. Only files marked as "Risky" are deep-scanned.

*   **Pros:** Most Intelligent (understands context), Minimal False Negatives.
*   **Cons:** Most Expensive (high token usage), Slowest.

### 2. `static_only`
**Decision Maker:** Classic Keyword Matching (`CodeFilter`).

**How it works:**
1. The scanner searches for dangerous keywords (e.g., `WebView`, `SQLite`, `Cipher`).
2. If found, the file is immediately marked for deep scan.
3. LLM is NOT used for filtering.

*   **Pros:** Super Fast, Zero Token Cost for filtering.
*   **Cons:** "Dumb" (no context), High False Positives, High False Negatives (obfuscation).

### 3. `hybrid` (Recommended)
**Decision Maker:** Static Analyzer + LLM Verification.

**How it works:**
1. **Phase 1 (Static):** Find files with dangerous keywords.
2. **Phase 2 (LLM Verification):** Only those specific files are summarized and checked by the LLM to confirm if they are truly risky.

*   **Pros:** Extreme Token Savings (ignores safe files), Good Accuracy.
*   **Cons:** Risk of Obfuscation (same as static_only).

### Usage Recommendations:
*   Use `llm_only` if have abundant tokens and need **100% accuracy**.
*   Use `hybrid` for **daily usage** (balanced).
*   Use `static_only` if are low on tokens or need a **very fast scan**.

## Decompiler Modes

Droid LLM Hunter supports dual decompilation to balance reliability and analysis quality. Configure this via `decompiler_mode` in `settings.yaml`.

### 1. `apktool` (Default / Classic)
*   **Format:** Smali (Assembly).
*   **Pros:** 100% Reliability, critical for Manifest analysis.
*   **Cons:** Harder for LLM to understand logic, higher token usage.

### 2. `jadx` (Modern)
*   **Format:** Java Source Code.
*   **Pros:** Native code format, LLM understands it perfectly, logic is clear.
*   **Cons:** May fail on some obfuscated apps.

### 3. `hybrid` (Smart Fallback - Recommended)
*   **Format:** Java (Primary) + Smali (Fallback).
*   **Logic:** The engine tries to use JADX output. If JADX fails or produces empty/corrupt code for a file, it automatically switches to the Smali version from Apktool.
*   **Result:** Best of both worlds—Analysis quality of Java with the reliability of Smali.


## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/roomkangali/droid-llm-hunter.git
    cd droid-llm-hunter
    ```

2.  **Create and activate a virtual environment:**
    *   **Linux/macOS:**
        ```bash
        python3 -m venv venv
        source venv/bin/activate
        ```
    *   **Windows:**
        ```bash
        python -m venv venv
        venv\\Scripts\\activate
        ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Apktool & JADX:**
    *   **Apktool (Required):** Must be installed. [Instructions](https://apktool.org/docs/install)
    *   **JADX (Optional but Recommended):** Required if you want to use `jadx` or `hybrid` decompiler modes. [GitHub](https://github.com/skylot/jadx)

## Configuration

The configuration for Droid LLM Hunter is located in the `config/settings.yaml` file. This file allows for configuration of the LLM provider, model, API keys, rules, and external tools paths.

**Note on JADX:** If `jadx` is not in your system PATH, you can specify the absolute path in `settings.yaml`:
```yaml
jadx:
  path: "/opt/jadx/bin/jadx"
```

## Usage

```bash
python dlh.py scan [APK file]
```

### Examples

*   **Scan an APK with verbose logging:**
    ```bash
    python dlh.py --verbose scan [APK file]
    ```

*   **Skip the decompilation step:**
    ```bash
    python dlh.py --no-decompile scan [APK file]
    ```

*   **Run only specific rules:**
    ```bash
    python dlh.py --rules "sql_injection,webview_xss" scan [APK file]
    ```

*   **List all available rules:**
    ```bash
    python dlh.py --list-rules
    ```

*   **Show Options and Commands:**
    ```bash
    python dlh.py --help
    ```

    ```bash
     Droid-LLM-Hunter: A tool to scan for vulnerabilities in Android applications.

    Options
    --verbose             -v            Enable verbose logging.
    --output              -o      TEXT  Output file for the scan results.
    --no-decompile                      Skip the decompilation step.
    --rules               -r      TEXT  Comma-separated list of rules to run.
    --profile             -p      TEXT  Configuration profile to use.
    --list-rules                        List all available rules and exit.
    --install-completion                Install completion for the current shell.
    --show-completion                   Show completion for the current shell, to copy it or customize the installation.

    Commands
    scan         Scan an APK file for vulnerabilities.
    list-rules   List all available rules.
    config       Manage the configuration of Droid-LLM-Hunter.
    ```

*   **Show Manage Configuration:**
    ```bash
    python dlh.py config --help
    ```

    ```bash
    Manage the configuration of Droid-LLM-Hunter.

    Commands
    provider            Set the LLM provider.
    model               Set the LLM model.
    rules               Enable or disable rules.
    show                Show the current configuration.
    validate            Validate the configuration file.
    attack-surface      Enable or disable the generation of the attack surface map.
    context-injection   Enable or disable Cross-Reference Context Injection (Call Graph).
    filter-mode         Set or show the code analysis filter mode.
    decompiler-mode     Set or show the decompiler mode (apktool, jadx, hybrid).
    wizard              Run the interactive configuration wizard.
    profile             Manage configuration profiles.
    ```

### Flags

*   `--verbose`, `-v`: Enable verbose logging.
*   `--output`, `-o`: Output file for the scan results.
*   `--no-decompile`: Skip the decompilation step.
*   `--rules`, `-r`: Comma-separated list of rules to run.
*   `--list-rules`: List all available rules and exit.
*   `--profile`, `-p`: Use a specific configuration profile for the scan.

### Commands

*   `scan`: Scan an APK file for vulnerabilities.
*   `config`: Manage the configuration of Droid-LLM-Hunter. This command has several sub-commands:
    *   `wizard`: Run the interactive configuration wizard.
    *   `provider <provider>`: Set the LLM provider.
    *   `model <model>`: Set the LLM model.
    *   `rules --enable <rules>` or `rules --disable <rules>`: Enable or disable rules.
    *   `validate`: Validate the configuration file.
    *   `show`: Show the current configuration.
    *   `profile`: Manage configuration profiles.
        *   `create <name>`: Create a new profile.
        *   `list`: List all available profiles.
        *   `switch <name>`: Switch to a different profile.
        *   `delete <name>`: Delete a profile.
    *   `attack-surface --enable` or `attack-surface --disable`: Enable or disable the generation of the attack surface map.
    *   `context-injection --enable` or `context-injection --disable`: Enable or disable Cross-Reference Context Injection (Smart Filtering) to improve accuracy.
    *   `filter-mode`: Set or show the code analysis filter mode.
    *   `decompiler-mode`: Set or show the decompiler mode (`apktool`, `jadx`, `hybrid`).
*   `list-rules`: List all available rules.

## Development Roadmap

This document outlines the future development plans for the Droid-LLM-Hunter.

*   **AI-Powered Dynamic Analysis:** Integration with ADB/Frida to verify static findings by running the app and simulating attacks (e.g., sending malicious Intents).
*   **Auto-Patching / Remediation:** Generating secure code fixes or `.diff` patches to automatically resolve identified vulnerabilities.
*   **CI/CD Integration:** Official Docker support and GitHub/GitLab templates for automated security scanning in DevOps pipeline.
*   **More Rules:** Constantly adding new vulnerability detection rules to cover the latest Android security threats.

## FAQ

**Is the AI analysis 100% accurate ?**

No. While Droid LLM Hunter drastically reduces noise using **Context Awareness** and **Smart Filtering**, LLMs (Artificial Intelligence) are probabilistic and can still make mistakes or "hallucinate". Treat the results as **leads** that require manual verification. The tool is designed to augment human intelligence, not replace it. Always verify findings manually!

**Why Performance scan APK slow ?**

**Note on Performance:** The speed of the analysis also heavily depends on:
*   **The LLM Provider/Model:** Local models (Ollama) depend on hardware (GPU/CPU). Cloud models (Groq/Gemini/OpenAI) are generally faster but depend on network latency.
*   **Active Rules:** Enabling more rules increases the number of queries sent to the LLM.
*   **Context Injection:** Using Cross-Reference Context (Call Graph) adds more data to process, slightly increasing analysis time for better accuracy.

**How can I add a new vulnerability rule ?**

To add a new vulnerability rule :
1.  Create a new YAML file in the `config/prompts/vuln_rules` directory (containing `name`, `description`, and `prompt`).
2.  Add the new rule to the `RulesSettings` class in `core/config_loader.py`.
3.  Add the new rule to the `config/settings.yaml` file.
4.  (Optional) Add a corresponding entry in `config/knowledge_base/masvs_mapping.json` to map the rule to an OWASP MASVS category.

## Contributing

Contributions are welcome! Please create an issue or pull request to report bugs or add new features.
