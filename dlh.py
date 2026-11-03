# pyrefly: ignore [missing-import]
import typer
from typer import rich_utils as _rich_utils
from rich.panel import Panel as _Panel
from rich.table import Table as _Table
from core.config_loader import load_settings
from core import log
from core.engine import Engine
from core.logger import setup_logger

app = typer.Typer(
    add_completion=False,            # hide --install-completion / --show-completion
    rich_markup_mode="rich",
)

# --- Boxed "Examples" panel on the top-level `dlh.py --help` -------------------
# Typer's `epilog` only renders as loose text, so to get a bordered panel that
# matches the Commands/Options boxes we render one ourselves by wrapping Typer's
# own rich help renderer. Gated to the root help (ctx.parent is None) so it does
# not appear on `scan --help` / `config --help`.
_HELP_EXAMPLES = [
    ("python dlh.py scan app.apk", "Basic scan"),
    ("python dlh.py scan app.apk --generate-exploit", "Scan + PoC"),
    ("python dlh.py scan app.apk --scan-libraries", "Library Hunter"),
    ('python dlh.py -r "sql_injection,webview_xss" scan app.apk', "Specific rules"),
    ("python dlh.py --list-rules", "List all rules"),
]

_orig_rich_format_help = _rich_utils.rich_format_help


def _rich_format_help_with_examples(*, obj, ctx, markup_mode):
    _orig_rich_format_help(obj=obj, ctx=ctx, markup_mode=markup_mode)
    if ctx.parent is None:  # top-level help only
        console = _rich_utils._get_rich_console()
        table = _Table(box=None, show_header=False, pad_edge=False, expand=False)
        table.add_column(style="cyan", no_wrap=True)
        table.add_column(style="dim")
        for cmd, desc in _HELP_EXAMPLES:
            table.add_row(cmd, desc)
        console.print(_Panel(table, title="Examples", title_align="left", border_style="cyan"))
        console.print("  Docs: https://github.com/roomkangali/droid-llm-hunter", style="dim")


_rich_utils.rich_format_help = _rich_format_help_with_examples

def list_rules_callback(value: bool):
    if value:
        from core.config_loader import RulesSettings
        print("Available rules:")
        for rule in RulesSettings.model_fields:
            print(f"- {rule}")
        raise typer.Exit()

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context,
         verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging.", rich_help_panel="Scan Options"),
         output: str = typer.Option(None, "--output", "-o", help="Output file for the scan results.", rich_help_panel="Scan Options"),
         no_decompile: bool = typer.Option(False, "--no-decompile", help="Skip the decompilation step.", rich_help_panel="Scan Options"),
         rules: str = typer.Option(None, "--rules", "-r", help="Comma-separated list of rules to run.", rich_help_panel="Scan Options"),
         profile: str = typer.Option(None, "--profile", "-p", help="Configuration profile to use.", rich_help_panel="Scan Options"),
         list_rules: bool = typer.Option(False, "--list-rules", help="List all available rules and exit.", callback=list_rules_callback, is_eager=True)):
    """
    Droid-LLM-Hunter: A tool to scan for vulnerabilities in Android applications.
    """
    if ctx.invoked_subcommand is None and not list_rules:
        # Check if version flag was not called (although we don't have one explicit yet, verbose is option)
        # If no arguments are passed that trigger action (like list_rules), show banner
        try:
             with open("banner.txt", "r", encoding="utf-8") as f:
                 print(f.read())
        except FileNotFoundError:
             log.warning("banner.txt not found.")
        except Exception as e:
             log.debug(f"Could not load banner: {e}")
        print("Run 'python dlh.py --help' to get started.\n")

    setup_logger(verbose)
    ctx.meta["output"] = output
    ctx.meta["no_decompile"] = no_decompile
    ctx.meta["rules"] = rules
    ctx.meta["profile"] = profile

@app.command(no_args_is_help=True)
def scan(ctx: typer.Context,
         apk_path: str = typer.Argument(..., help="Path to the APK, XAPK, or APKS file to analyze."),
         generate_exploit: bool = typer.Option(False, "--generate-exploit", help="Generate PoC scripts for detected vulnerabilities."),
         scan_libraries: bool = typer.Option(False, "--scan-libraries", help="Include 3rd party libraries in scan scope (e.g. androidx, google, okhttp)."),
         no_cache: bool = typer.Option(False, "--no-cache", help="Disable the LLM response cache (force fresh calls, no resume).")):
    """
    Scan an APK, XAPK, or APKS file for vulnerabilities.
    """
    output = ctx.meta["output"]
    no_decompile = ctx.meta["no_decompile"]
    rules = ctx.meta["rules"]
    profile = ctx.meta["profile"]
    log.info("Initializing Droid-LLM-Hunter...")
    try:
        settings = load_settings(profile)
        
        if generate_exploit:
            settings.analysis.generate_exploit = True
        
        if scan_libraries:
            settings.analysis.scan_libraries = True
            log.info("Library Hunter Mode: ENABLED 📚")

        if no_cache:
            settings.analysis.use_cache = False
            log.info("Response cache: DISABLED (--no-cache)")

        log.info("Configuration loaded successfully.")
        engine = Engine(settings)
        engine.run(apk_path, output, no_decompile, rules)
    except Exception as e:
        log.error(f"An error occurred during the scan: {e}")
        raise typer.Exit(code=1)

config_app = typer.Typer(help="Manage the configuration of Droid-LLM-Hunter.", no_args_is_help=True)
app.add_typer(config_app, name="config")

@config_app.command("provider")
def set_provider(provider: str = typer.Argument(None, help="The LLM provider to use.")):
    """
    Set or show the LLM provider.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f) or {}
    except FileNotFoundError:
        settings = {}

    if provider is None:
        current_provider = settings.get("llm", {}).get("provider")
        print(f"Current LLM provider: {current_provider}")
        return

    settings.setdefault("llm", {})["provider"] = provider
    
    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
        
    print(f"LLM provider set to: {provider}")

@config_app.command("model")
def set_model(model: str = typer.Argument(None, help="The LLM model to use.")):
    """
    Set or show the LLM model.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f) or {}
    except FileNotFoundError:
        settings = {}

    provider = settings.get("llm", {}).get("provider")

    # Map provider name -> settings key
    provider_model_key = {
        "ollama": "model",
        "gemini": "gemini_model",
        "groq": "groq_model",
        "openai": "openai_model",
        "anthropic": "anthropic_model",
        "openrouter": "openrouter_model",
        "router9": "router9_model",
        "codex": "codex_model",
    }
    
    if model is None:
        # Show current model
        if not provider:
            print("LLM provider is not set.")
        else:
            key = provider_model_key.get(provider)
            current_model = settings["llm"].get(key) if key else None
            print(f"Current LLM model for {provider}: {current_model}")
        return

    if not provider:
        print("Please set the LLM provider first using 'config provider <provider>'")
        raise typer.Exit()

    key = provider_model_key.get(provider)
    if not key:
        print(f"Unknown provider '{provider}'. Supported: {', '.join(provider_model_key.keys())}")
        raise typer.Exit()

    settings.setdefault("llm", {})[key] = model

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)

    print(f"LLM model for {provider} set to: {model}")

@config_app.command("rules")
def set_rules(rules: str = typer.Argument(None, help="Comma-separated list of rules."), enable: bool = typer.Option(False, "--enable"), disable: bool = typer.Option(False, "--disable")):
    """
    Enable or disable rules, or list enabled rules.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"rules": {}}

    if "rules" not in settings:
        settings["rules"] = {}

    if rules is None:
        # Show enabled rules
        print("Enabled rules:")
        for rule, is_enabled in settings["rules"].items():
            if is_enabled:
                print(f"- {rule}")
        return

    rules_to_change = [r.strip() for r in rules.split(',')]
    
    for rule in rules_to_change:
        if enable:
            settings["rules"][rule] = True
            print(f"Enabled rule: {rule}")
        elif disable:
            settings["rules"][rule] = False
            print(f"Disabled rule: {rule}")

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
        
    print("Rules updated successfully.")

@config_app.command("show")
def show_config():
    """
    Show the current configuration.
    """
    try:
        settings = load_settings()
        print(settings.model_dump_json(indent=2))
    except Exception as e:
        print(f"Could not load configuration: {e}")

@config_app.command("validate")
def validate_config():
    """
    Validate the configuration file.
    """
    try:
        load_settings()
        print("Configuration is valid.")
    except Exception as e:
        print(f"Configuration is invalid: {e}")

@config_app.command("attack-surface")
def set_attack_surface(enable: bool = typer.Option(False, "--enable"), disable: bool = typer.Option(False, "--disable")):
    """
    Enable or disable the generation of the attack surface map.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if not enable and not disable:
        current_status = settings.get("analysis", {}).get("generate_attack_surface_map", False)
        status_text = "enabled" if current_status else "disabled"
        print(f"Attack surface map generation is currently {status_text}.")
        return

    if enable:
        settings["analysis"]["generate_attack_surface_map"] = True
        print("Attack surface map generation enabled.")
    elif disable:
        settings["analysis"]["generate_attack_surface_map"] = False
        print("Attack surface map generation disabled.")

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)

@config_app.command("context-injection")
def set_context_injection(enable: bool = typer.Option(False, "--enable"), disable: bool = typer.Option(False, "--disable")):
    """
    Enable or disable Cross-Reference Context Injection (Call Graph).
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if not enable and not disable:
        current_status = settings.get("analysis", {}).get("use_cross_reference_context", True)
        status_text = "enabled" if current_status else "disabled"
        print(f"Cross-Reference Context Injection is currently {status_text}.")
        return

    if enable:
        settings["analysis"]["use_cross_reference_context"] = True
        print("Cross-Reference Context Injection enabled.")
    elif disable:
        settings["analysis"]["use_cross_reference_context"] = False
        print("Cross-Reference Context Injection disabled.")

    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)


@config_app.command("filter-mode")
def set_filter_mode(mode: str = typer.Argument(None, help="The filter mode to use (static_only, llm_only, hybrid).")):
    """
    Set or show the code analysis filter mode.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if mode is None:
        current_mode = settings.get("analysis", {}).get("filter_mode", "llm_only")
        print(f"Current filter mode: {current_mode}")
        return

    valid_modes = ["static_only", "llm_only", "hybrid"]
    if mode not in valid_modes:
        print(f"Invalid mode. Choose from: {', '.join(valid_modes)}")
        raise typer.Exit()

    settings["analysis"]["filter_mode"] = mode
    
    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
    
    print(f"Filter mode set to: {mode}")

@config_app.command("decompiler-mode")
def set_decompiler_mode(mode: str = typer.Argument(None, help="The decompiler mode to use (apktool, jadx, hybrid).")):
    """
    Set or show the decompiler mode.
    """
    import yaml
    try:
        with open("config/settings.yaml", "r") as f:
            settings = yaml.safe_load(f)
    except FileNotFoundError:
        settings = {"analysis": {}}

    if "analysis" not in settings:
        settings["analysis"] = {}

    if mode is None:
        current_mode = settings.get("analysis", {}).get("decompiler_mode", "apktool")
        print(f"Current decompiler mode: {current_mode}")
        return

    valid_modes = ["apktool", "jadx", "hybrid"]
    if mode not in valid_modes:
        print(f"Invalid mode. Choose from: {', '.join(valid_modes)}")
        raise typer.Exit()

    settings["analysis"]["decompiler_mode"] = mode
    
    with open("config/settings.yaml", "w") as f:
        yaml.dump(settings, f)
    
    print(f"Decompiler mode set to: {mode}")


@config_app.command("wizard")
def config_wizard():
    """
    Run the interactive configuration wizard.
    """
    import yaml
    
    print("Welcome to the Droid LLM Hunter configuration wizard!")
    
    provider = typer.prompt("Select LLM provider (ollama, gemini, groq, openai, anthropic, openrouter, router9, codex)")
    
    if provider == "ollama":
        model = typer.prompt("Enter Ollama model name")
        ollama_url = typer.prompt("Enter Ollama URL", default="http://localhost:11434")
        settings = {
            "llm": {
                "provider": provider,
                "model": model,
                "ollama_url": ollama_url
            }
        }
    elif provider == "gemini":
        gemini_model = typer.prompt("Enter Gemini model name", default="gemini-2.5-flash")
        gemini_api_key = typer.prompt("Enter Gemini API key")
        settings = {
            "llm": {
                "provider": provider,
                "gemini_model": gemini_model,
                "gemini_api_key": gemini_api_key
            }
        }
    elif provider == "groq":
        groq_model = typer.prompt("Enter Groq model name", default="llama-3.1-8b-instant")
        groq_api_key = typer.prompt("Enter Groq API key")
        settings = {
            "llm": {
                "provider": provider,
                "groq_model": groq_model,
                "groq_api_key": groq_api_key
            }
        }
    elif provider == "openai":
        openai_model = typer.prompt("Enter OpenAI model name", default="gpt-4-turbo")
        openai_api_key = typer.prompt("Enter OpenAI API key")
        settings = {
            "llm": {
                "provider": provider,
                "openai_model": openai_model,
                "openai_api_key": openai_api_key
            }
        }
    elif provider == "anthropic":
        anthropic_model = typer.prompt("Enter Anthropic model name", default="claude-opus-4-6")
        anthropic_api_key = typer.prompt("Enter Anthropic API key")
        settings = {
            "llm": {
                "provider": provider,
                "anthropic_model": anthropic_model,
                "anthropic_api_key": anthropic_api_key
            }
        }
    elif provider == "openrouter":
        openrouter_model = typer.prompt("Enter OpenRouter model name", default="google/gemini-2.5-flash")
        openrouter_api_key = typer.prompt("Enter OpenRouter API key")
        settings = {
            "llm": {
                "provider": provider,
                "openrouter_model": openrouter_model,
                "openrouter_api_key": openrouter_api_key
            }
        }
    elif provider == "router9":
        router9_model = typer.prompt("Enter 9Router model name (e.g. gc/gemini-2.5-pro)")
        router9_api_key = typer.prompt("Enter 9Router API key")
        router9_base_url = typer.prompt(
            "Enter 9Router base URL",
            default="http://localhost:20128/v1/chat/completions"
        )
        settings = {
            "llm": {
                "provider": provider,
                "router9_model": router9_model,
                "router9_api_key": router9_api_key,
                "router9_base_url": router9_base_url
            }
        }
    elif provider == "codex":
        # No API key prompt: Codex CLI authenticates itself via `codex login`.
        codex_model = typer.prompt(
            "Enter Codex model name (blank = use ~/.codex/config.toml default)",
            default="", show_default=False
        )
        codex_cli_path = typer.prompt("Path to Codex CLI binary", default="codex")
        settings = {
            "llm": {
                "provider": provider,
                "codex_model": codex_model or None,
                "codex_cli_path": codex_cli_path
            }
        }
    else:
        print(f"Invalid provider '{provider}'. Choose from: ollama, gemini, groq, openai, anthropic, openrouter, router9, codex")
        raise typer.Exit()

    try:
        with open("config/settings.yaml", "r") as f:
            existing_settings = yaml.safe_load(f) or {}
    except FileNotFoundError:
        existing_settings = {}

    # Deep merge: only update 'llm' key, preserve other settings
    if "llm" not in existing_settings:
        existing_settings["llm"] = {}
    existing_settings["llm"].update(settings["llm"])

    with open("config/settings.yaml", "w") as f:
        yaml.dump(existing_settings, f)
        
    print("Configuration saved successfully to config/settings.yaml")

profile_app = typer.Typer(help="Manage configuration profiles.")
config_app.add_typer(profile_app, name="profile")

@profile_app.callback(invoke_without_command=True)
def profile_callback(ctx: typer.Context):
    """
    Manage configuration profiles.
    """
    if ctx.invoked_subcommand is None:
        list_profiles()

@profile_app.command("create")
def create_profile(name: str):
    """
    Create a new configuration profile.
    """
    import yaml
    import os

    profile_dir = "config/profiles"
    os.makedirs(profile_dir, exist_ok=True)
    
    profile_path = os.path.join(profile_dir, f"{name}.yaml")
    if os.path.exists(profile_path):
        print(f"Profile '{name}' already exists.")
        raise typer.Exit()
        
    print(f"Creating new profile: {name}")
    
    import shutil

    # Backup existing settings.yaml so we can restore it after wizard
    backup_path = "config/settings.yaml.bak"
    has_backup = False
    if os.path.exists("config/settings.yaml"):
        shutil.copy("config/settings.yaml", backup_path)
        has_backup = True

    # Run the wizard — it writes to settings.yaml
    config_wizard()
    
    # Copy wizard output to the new profile file
    shutil.copy("config/settings.yaml", profile_path)

    # Restore the original settings.yaml from backup
    if has_backup:
        shutil.copy(backup_path, "config/settings.yaml")
        os.remove(backup_path)

    print(f"Profile '{name}' created successfully.")

@profile_app.command("list")
def list_profiles():
    """
    List all available profiles.
    """
    import os

    profile_dir = "config/profiles"
    if not os.path.exists(profile_dir):
        print("No profiles found.")
        raise typer.Exit()

    profiles = [f.replace(".yaml", "") for f in os.listdir(profile_dir) if f.endswith(".yaml")]
    
    if not profiles:
        print("No profiles found.")
        raise typer.Exit()

    print("Available profiles:")
    for profile in profiles:
        print(f"- {profile}")

@profile_app.command("switch")
def switch_profile(name: str):
    """
    Switch to a different profile.
    """
    import os
    import shutil

    profile_dir = "config/profiles"
    profile_path = os.path.join(profile_dir, f"{name}.yaml")

    if not os.path.exists(profile_path):
        print(f"Profile '{name}' not found.")
        raise typer.Exit()

    shutil.copy(profile_path, "config/settings.yaml")
    print(f"Switched to profile: {name}")

@profile_app.command("delete")
def delete_profile(name: str):
    """
    Delete a profile.
    """
    import os

    profile_dir = "config/profiles"
    profile_path = os.path.join(profile_dir, f"{name}.yaml")

    if not os.path.exists(profile_path):
        print(f"Profile '{name}' not found.")
        raise typer.Exit()

    os.remove(profile_path)
    print(f"Profile '{name}' deleted successfully.")


# NOTE: list-rules is exposed via --list-rules flag on the root command (see list_rules_callback).
# A subcommand alias is kept below for discoverability and backward compatibility.
@app.command("list-rules")
def list_rules_cmd():
    """
    List all available rules. (Alias: dlh --list-rules)
    """
    from core.config_loader import RulesSettings
    print("Available rules:")
    for rule in RulesSettings.model_fields:
        print(f"- {rule}")


if __name__ == "__main__":
    app()
