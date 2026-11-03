# Droid LLM Hunter

**Droid LLM Hunter** is an automated security analysis tool designed to detect vulnerabilities in Android applications with high precision. By combining traditional static analysis (SAST) with the contextual understanding of **Large Language Models (LLMs)**, it bridges the gap between keyword-based scanning and human-like code review.

It supports **Hybrid Decompilation** (Smali/Java), **Context-Aware Analysis** (Call Graphs), and **Exhaustive Hybrid Scheduling**. In hybrid mode, static signals discover the scoped candidate set, high-signal files are prioritized, and every scoped candidate still reaches deep rule analysis—priority is never a top-N or score gate.

Features **Auto-Exploit Generation**, transforming from a passive scanner into an active **Red Team Assistant** capable of verifying vulnerabilities with generated Proof-of-Concept (PoC) scripts.

### 📊 Dashboard Report

**Dashboard Report Droid-LLM-Hunter** - web interface to visualize and manage security analysis reports.
**Link**: [dashboard-report-dlh](https://github.com/roomkangali/dashboard-report-dlh)

### 📱 VulnerApp for Testing

**VulnerAppDLH** - a vulnerable Android application created specifically to test Droid-LLM-Hunter.
**Link**: [VulnerAppDLH](https://github.com/roomkangali/VulnerAppDLH)

### 📥 DLH Apk Fetcher

**DLH Apk Fetcher** - a Python CLI tool for detecting Android devices connected via ADB, listing installed apps (name + version), showing currently running apps, searching packages, and downloading APKs into a structured local folder — preparing APK samples for security analysis with Droid-LLM-Hunter.
**Link**: [dlh-apk-fetcher](https://github.com/roomkangali/dlh-apk-fetcher)

<p align="center">
  <img src="https://img.shields.io/badge/Security-Android-green" />
  <img src="https://img.shields.io/badge/Droid LLM Hunter-DLH-red" />
  <img src="https://img.shields.io/badge/version-1.3.0-cyan" />
</p>

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

<div align="center">
  <table>
    <tr>
      <td align="center" valign="top">
        <strong>Tutorial Install Droid LLM Hunter</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=HaasUKfLTSU" target="_blank">
          <img src="https://img.youtube.com/vi/HaasUKfLTSU/hqdefault.jpg" alt="Demo 1" width="100%"/>
        </a>
      </td>
      <td align="center" valign="top">
        <strong>WebView via DeepLink - Exported Components</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=RYyJsm53w4I" target="_blank">
          <img src="https://img.youtube.com/vi/RYyJsm53w4I/hqdefault.jpg" alt="Demo 2" width="100%"/>
        </a>
      </td>
    </tr>
  </table>
</div>

---

## 📋 Table of Contents

- [✨ Features](document/FEATURES.md)
- [🔄 Scan Workflow](document/SCAN-WORKFLOW.md)
- [🛡️ Available Rules](document/RULES.md)
- [⚙️ Configuration](document/CONFIGURATION.md)
- [🔩 Installation](document/INSTALLATION.md)
- [💡 Usage](document/USAGE.md)
- [🔁 CI/CD Integration](document/CICD.md)
- [🚀 Development Roadmap](document/ROADMAP-V2.md)
- [❓ FAQ](document/FAQ.md)
- [🤝 Contributing](#contributing)

---

## ✨ Features

Droid LLM Hunter combines static analysis with LLM intelligence to detect Android vulnerabilities with high precision. Key capabilities include Staged Prompt Architecture, exhaustive Hybrid Filter Mode, bounded parallel summarization, Call Graph Context Injection, OWASP MASVS enrichment, honest `Error/Unanalyzed` reporting, and Auto-Exploit Generation across 8 LLM providers (including **9Router**, a self-hosted multi-provider router, and **Codex CLI**, a local agent binary that needs no API key).

→ **[View Full Feature List](document/FEATURES.md)**

---

## 🔄 Scan Workflow

Multi-stage pipeline: **Decompilation → Rule-Signal Discovery → Scope Filter → Parallel Summarization → Exhaustive Priority Queue → Deep Rule Analysis → Global Context → Chained Exploit → Report**.

→ **[View Full Pipeline Diagram & Explanation](document/SCAN-WORKFLOW.md)**

---

<div align="center">
  <table>
    <tr>
      <td align="center" valign="top">
        <strong>Hardcoded Secrets</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=djDF4YZYPaM" target="_blank">
          <img src="https://img.youtube.com/vi/djDF4YZYPaM/hqdefault.jpg" alt="Demo 1" width="100%"/>
        </a>
      </td>
      <td align="center" valign="top">
        <strong>SQL Injection - Generate-Exploit</strong>
        <br><br>
        <a href="https://www.youtube.com/watch?v=JNBZ_gfMffk" target="_blank">
          <img src="https://img.youtube.com/vi/JNBZ_gfMffk/hqdefault.jpg" alt="Demo 2" width="100%"/>
        </a>
      </td>
    </tr>
  </table>
</div>

---

## 🛡️ Available Rules

26 vulnerability rules covering SQL Injection, WebView XSS, Hardcoded Secrets, Intent Spoofing, **Intent Redirection**, Path Traversal, Insecure Deserialization, and more — all mapped to OWASP MASVS. A separate **Library Hunter** mode (`--scan-libraries`) adds supply-chain/backdoor detection.

→ **[View All Rules](document/RULES.md)**

---

## ⚙️ Configuration

| Setting | Options | Recommended |
|---------|---------|-------------|
| `filter_mode` | `llm_only`, `static_only`, `hybrid` | `hybrid` for contextual audit; `static_only` for a large first pass |
| `decompiler_mode` | `apktool`, `jadx`, `hybrid` | `hybrid` |
| `provider` | `ollama`, `gemini`, `groq`, `openai`, `anthropic`, `openrouter`, `router9`, `codex` | `anthropic` |

→ **[View Full Configuration Guide](document/CONFIGURATION.md)**

---

## 🔩 Installation

```bash
git clone https://github.com/roomkangali/droid-llm-hunter.git
cd droid-llm-hunter
pip install -r requirements.txt
```

Requires: Python 3.11+, Apktool, and optionally JADX.

→ **[Full Installation Guide (including Docker)](document/INSTALLATION.md)**

---

## 💡 Usage

```bash
python dlh.py scan target.apk
python dlh.py scan target.apk --generate-exploit
python dlh.py -v --rules "sql_injection,webview_xss" scan target.apk
```

→ **[Full Usage Guide & Command Reference](document/USAGE.md)**

---

## 🔁 CI/CD Integration

Supports GitHub Actions and GitLab CI. Returns `exit code 1` on scan failure for automated quality gates.

→ **[View CI/CD Integration Guide](document/CICD.md)**

---

## 🚀 Development Roadmap

Next major version (v2.0) targets AI-Powered Dynamic Analysis with Frida & ADB integration, Taint Analysis Engine, and De-obfuscation Support.

→ **[View Full v2.0 Roadmap](document/ROADMAP-V2.md)**

---

## ❓ FAQ

→ **[View FAQ](document/FAQ.md)**

---

## Contributing

🤝 Contributions are welcome! Please create an issue or pull request to report bugs or add new features.

---

*While Droid LLM Hunter uses Context Awareness and Smart Filtering to minimize noise, LLMs are inherently probabilistic and may occasionally hallucinate or misidentify vulnerabilities. Treat all results as leads requiring manual verification. This tool is built to augment human analysis not replace it.*
