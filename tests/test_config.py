"""
Golden test — Layer 1 (deterministic, no LLM).

Locks in config-schema invariants: the shipped settings validate, rules stay A-Z
(list-rules order), the rule count is stable, and the Gemini key field is consistent
with the other providers (v1.2.0 #16 rename).
"""
import pytest
from pydantic import ValidationError

from core.config_loader import AnalysisSettings, load_settings, RulesSettings, LLMSettings


def test_shipped_settings_are_valid():
    s = load_settings()
    assert s.llm.provider
    assert s.analysis is not None
    assert s.rules is not None


def test_rules_are_alphabetical():
    fields = list(RulesSettings.model_fields)
    assert fields == sorted(fields), "RulesSettings must stay A-Z (drives list-rules order)"


def test_rule_count_stable():
    assert len(RulesSettings.model_fields) == 26


def test_gemini_api_key_field_is_consistent():
    # v1.2.0 #16: Gemini used the generic `api_key`; renamed to `gemini_api_key`.
    assert "gemini_api_key" in LLMSettings.model_fields
    assert "api_key" not in LLMSettings.model_fields


def test_app_summary_prompt_is_format_safe_and_dense():
    """v1.3.0: app_summary_prompt.txt was rewritten to produce a dense executive
    summary (was ~1000-1600 tokens of markdown essay; observed ~360 tokens after).
    Guard against regressions: must still .format() safely (no stray braces) and
    must explicitly instruct a word budget + against permission-absence enumeration."""
    with open("config/prompts/app_summary_prompt.txt") as f:
        prompt = f.read()
    prompt.format(manifest="<manifest/>", summaries="x")  # raises on stray { }
    assert "words" in prompt.lower()  # an explicit length budget is present
    assert "do not enumerate" in prompt.lower()


def test_attack_surface_prompt_is_format_safe_and_json_only():
    """v1.3.0: attack_surface_prompt.txt was rewritten from a narrative-report prompt
    to a compact JSON-inventory prompt (see Engine.generate_attack_surface_map).
    It must still .format() safely (no stray braces — no literal JSON example is
    used in the template for exactly this reason) and must demand JSON-only output."""
    with open("config/prompts/attack_surface_prompt.txt") as f:
        prompt = f.read()
    prompt.format(manifest="<manifest/>", summaries="x")  # raises on stray { }
    assert "json" in prompt.lower()
    assert "no prose" in prompt.lower() or "not a report" in prompt.lower()


def test_exploit_provider_fields_exist_and_default_unset():
    # v1.3.0: route --generate-exploit to a different provider/model than scanning
    # (some models refuse/empty exploit-gen requests). Both optional, default None
    # so this is fully backward compatible / opt-in.
    assert "exploit_provider" in LLMSettings.model_fields
    assert "exploit_model" in LLMSettings.model_fields
    assert LLMSettings.model_fields["exploit_provider"].default is None
    assert LLMSettings.model_fields["exploit_model"].default is None


def test_router9_provider_fields_exist():
    # v1.3.0: 9Router (self-hosted, OpenAI-compatible multi-provider router).
    # Field prefix is "router9" (not "9router") because Pydantic/Python identifiers
    # can't start with a digit.
    for field in ("router9_model", "router9_api_key", "router9_base_url"):
        assert field in LLMSettings.model_fields


def test_codex_provider_fields_exist():
    # Codex is a LOCAL CLI agent, not an HTTP API: it authenticates via `codex login`,
    # so there is deliberately no codex_api_key field. codex_model is optional because
    # an unset model means "use whatever ~/.codex/config.toml already selects".
    for field in ("codex_model", "codex_cli_path", "codex_timeout",
                  "codex_sandbox", "codex_reasoning_effort"):
        assert field in LLMSettings.model_fields
    assert "codex_api_key" not in LLMSettings.model_fields
    assert LLMSettings.model_fields["codex_model"].default is None
    assert LLMSettings.model_fields["codex_cli_path"].default == "codex"
    assert LLMSettings.model_fields["codex_sandbox"].default == "read-only"


def test_new_v120_settings_exist():
    for field in ("max_workers", "summary_workers", "summary_batch_size", "hybrid_risk_triage", "use_cache", "max_input_chars"):
        assert field in __import__("core.config_loader", fromlist=["AnalysisSettings"]).AnalysisSettings.model_fields
    assert "max_tokens" in LLMSettings.model_fields


def test_summary_workers_is_bounded_without_changing_deep_workers():
    assert AnalysisSettings().summary_workers == 2
    assert AnalysisSettings(summary_workers=1).summary_workers == 1
    assert AnalysisSettings(summary_workers=32).summary_workers == 32
    with pytest.raises(ValidationError):
        AnalysisSettings(summary_workers=0)
    with pytest.raises(ValidationError):
        AnalysisSettings(summary_workers=33)
    assert AnalysisSettings(summary_workers=7, max_workers=3).max_workers == 3


def test_summary_batch_size_is_opt_in_and_bounded():
    assert AnalysisSettings().summary_batch_size == 1
    assert AnalysisSettings(summary_batch_size=2).summary_batch_size == 2
    assert AnalysisSettings(summary_batch_size=8).summary_batch_size == 8
    assert AnalysisSettings(summary_batch_size=32).summary_batch_size == 32
    with pytest.raises(ValidationError):
        AnalysisSettings(summary_batch_size=0)
    with pytest.raises(ValidationError):
        AnalysisSettings(summary_batch_size=33)


def test_hybrid_risk_triage_defaults_off_but_keeps_legacy_rollback():
    assert AnalysisSettings().hybrid_risk_triage is False
    assert AnalysisSettings(hybrid_risk_triage=True).hybrid_risk_triage is True


def test_golden_baseline_is_well_formed():
    """Deterministic guard for the Layer-2 baseline: every rule key is real (Layer-2 test itself is opt-in)."""
    import json
    import os

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    baseline = json.load(open(os.path.join(repo, "tests", "golden", "vulnerapp_expected.json")))
    valid_rules = set(RulesSettings.model_fields)

    for rule in baseline["expected"]:
        assert rule in valid_rules, f"baseline 'expected' has unknown rule: {rule}"
        assert isinstance(baseline["expected"][rule], list) and baseline["expected"][rule]
    for rule in baseline.get("must_not_fire", {}):
        if not rule.startswith("_"):
            assert rule in valid_rules, f"baseline 'must_not_fire' has unknown rule: {rule}"
    for rule in baseline.get("uncovered_rules", {}).get("rules", []):
        assert rule in valid_rules, f"baseline 'uncovered_rules' has unknown rule: {rule}"
