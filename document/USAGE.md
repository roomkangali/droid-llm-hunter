# 💡 Droid LLM Hunter - Usage Guide

→ [Back to README](../README.md)

---

## Basic Command

```bash
python dlh.py scan [APK file]
```

---

## Examples

- **Scan with verbose logging:**
  ```bash
  python dlh.py -v scan target.apk
  ```

- **Scan and generate PoC exploit scripts:**
  ```bash
  python dlh.py scan target.apk --generate-exploit
  ```

- **Library Hunter Mode — scan 3rd-party libraries (supply-chain audit):**
  ```bash
  python dlh.py scan target.apk --scan-libraries
  ```
  > Bypasses Smart Scope Protection to hunt backdoors/droppers (e.g. `DexClassLoader`) inside SDKs, using strict regex to save tokens.

- **Combine flags (full offensive run):**
  ```bash
  python dlh.py scan target.apk --generate-exploit --scan-libraries
  ```

- **Skip the decompilation step:**
  ```bash
  python dlh.py --no-decompile scan target.apk
  ```

- **Disable the LLM response cache (force fresh calls, no resume):**
  ```bash
  python dlh.py scan target.apk --no-cache
  ```
  > By default the cache is ON: a scan interrupted by a crash or rate limit resumes for free when you re-run the same command. See [Response Cache](CONFIGURATION.md#response-cache-analysisuse_cache).

- **Run only specific rules:**
  ```bash
  python dlh.py --rules "sql_injection,webview_xss" scan target.apk
  ```
  > `--rules` narrows the run to the requested rules that are already enabled in `settings.yaml`; it does not enable disabled rules. This is an operator-selected scope and may intentionally omit other vulnerability classes.

- **Select exhaustive hybrid candidate processing:**
  ```bash
  python dlh.py config filter-mode hybrid
  python dlh.py scan target.apk
  ```
  > Hybrid summarizes the scoped rule-signal candidates, prioritizes static-pattern hits, and still deep-scans every scoped candidate. For the conservative worker/batching settings, see [Configuration](CONFIGURATION.md#choosing-a-profile-for-a-large-apk).

- **Use the faster initial profile for a very large APK:**
  ```bash
  python dlh.py config filter-mode static_only
  python dlh.py scan target.apk
  ```
  > `static_only` skips preliminary summary/triage calls but still uses the LLM for applicable deep rule verdicts. It provides less summary-based context than hybrid.

- **Save output to a specific file:**
  ```bash
  python dlh.py --output results.json scan target.apk
  ```

- **Use a configuration profile:**
  ```bash
  python dlh.py --profile pentest scan target.apk
  ```

- **List all available rules:**
  ```bash
  python dlh.py --list-rules
  ```

---

## Flags

> **Ordering matters:** global flags go **before** the `scan` command; scan options go **after** `scan <apk>`.
> Example: `python dlh.py -v --rules "sql_injection" scan target.apk --generate-exploit`

### Global Flags (before the command)

```
+--------------------+------+----------------------------------------------------+
| Flag               | Short| Description                                        |
+--------------------+------+----------------------------------------------------+
| --verbose          | -v   | Enable verbose logging.                            |
| --output           | -o   | Output file for the scan results.                  |
| --no-decompile     | —    | Skip the decompilation step.                       |
| --rules            | -r   | Comma-separated list of rules to run.              |
| --list-rules       | —    | List all available rules and exit.                 |
| --profile          | -p   | Use a specific configuration profile.              |
+--------------------+------+----------------------------------------------------+
```

### Scan Options (after `scan <apk>`)

```
+---------------------+----------------------------------------------------------+
| Option              | Description                                               |
+---------------------+----------------------------------------------------------+
| --generate-exploit  | Generate PoC scripts for confirmed vulnerabilities.      |
| --scan-libraries    | Library Hunter Mode: include 3rd-party libraries in the  |
|                     | scan scope (supply-chain / backdoor audit).              |
| --no-cache          | Disable the LLM response cache (force fresh calls, no    |
|                     | resume) for this run.                                    |
+---------------------+----------------------------------------------------------+
```

---

## Commands

> **Tip:** `provider`, `model`, `filter-mode`, and `decompiler-mode` **print the current value** when called with no argument (e.g. `config filter-mode`). `attack-surface` and `context-injection` print status when called with no `--enable/--disable`.

```
+---------------------------------------+------------------------------------------------------------+
| Command                               | Description                                                |
+---------------------------------------+------------------------------------------------------------+
| scan <apk>                            | Scan an APK file for vulnerabilities.                      |
| scan <apk> --generate-exploit         | Generate PoC scripts for confirmed vulnerabilities.        |
| scan <apk> --scan-libraries           | Library Hunter Mode (scan 3rd-party libraries).            |
| scan <apk> --no-cache                 | Disable the LLM response cache for this run.               |
| list-rules                            | List all available rules.                                  |
|                                       |                                                            |
| config wizard                         | Run the interactive configuration wizard.                  |
| config show                           | Show the current (merged) configuration.                   |
| config validate                       | Validate the configuration file.                           |
| config provider [provider]            | Set — or show, if omitted — the LLM provider.              |
| config model [model]                  | Set — or show, if omitted — the LLM model.                 |
| config rules --enable <rules>         | Enable the given comma-separated rules.                    |
| config rules --disable <rules>        | Disable the given comma-separated rules.                   |
| config rules                          | List currently enabled rules.                              |
| config filter-mode [mode]             | Set/show filter mode (static_only, llm_only, hybrid).      |
| config decompiler-mode [mode]         | Set/show decompiler mode (apktool, jadx, hybrid).          |
| config attack-surface --enable        | Enable attack surface map generation.                      |
| config attack-surface --disable       | Disable attack surface map generation.                     |
| config context-injection --enable     | Enable Cross-Reference Context Injection (Call Graph).     |
| config context-injection --disable    | Disable Cross-Reference Context Injection.                 |
|                                       |                                                            |
| config profile                        | List available profiles.                                   |
| config profile create <name>          | Create a new profile (runs the wizard).                    |
| config profile list                   | List all available profiles.                               |
| config profile switch <name>          | Switch the active config to a profile.                     |
| config profile delete <name>          | Delete a profile.                                          |
+---------------------------------------+------------------------------------------------------------+
```

> **Note:** Performance/cost knobs—`summary_workers`, `summary_batch_size`, `hybrid_risk_triage`, `max_workers`, `max_input_chars` (`analysis:`), and `max_tokens` (`llm:`)—are set in `config/settings.yaml`, not via CLI. The recall-validated hybrid defaults are `summary_workers: 2`, `summary_batch_size: 1`, and `hybrid_risk_triage: false`. See [Configuration → Performance & Cost Controls](CONFIGURATION.md#performance--cost-controls).
