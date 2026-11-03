"""
Golden test — Layer 1 (deterministic, no LLM).

Locks in the v1.2.0 engine fixes so future refactors can't silently regress them:
per-rule gating (#1), input truncation (#5), failure/parse handling (#2 / Ollama-JSON),
the response cache (#4), and cross-language call-graph mapping.
"""
import types

import pytest

from core.engine import Engine
from core.llm_cache import CachedLLMClient
from core.call_graph import CallGraphBuilder
from modules.llm_client.router9 import Router9Client
from modules.llm_client.anthropic import AnthropicClient
from modules.llm_client.gemini import GeminiClient
from modules.llm_client.groq import GroqClient
from modules.llm_client.ollama import OllamaClient
from modules.llm_client.openai import OpenAIClient


def _engine():
    # Bypass __init__ (which builds a real LLM client); we only test pure methods.
    return object.__new__(Engine)


# ---- #1 per-rule regex gating -------------------------------------------------
def test_rule_should_run_gating():
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(filter_mode="hybrid"))
    pd = {"detection_pattern": r"execSQL\s*\("}
    assert e._rule_should_run("sql", pd, "db.execSQL(x)") is True
    assert e._rule_should_run("sql", pd, "int x = 1;") is False
    assert e._rule_should_run("logic", {"prompt": "..."}, "anything") is True  # no pattern -> run
    # llm_only bypasses gating entirely
    e.settings.analysis.filter_mode = "llm_only"
    assert e._rule_should_run("sql", pd, "int x = 1;") is True
    # bad regex fails open (runs the LLM rather than silently dropping the rule)
    e.settings.analysis.filter_mode = "hybrid"
    assert e._rule_should_run("x", {"detection_pattern": r"([unclosed"}, "y") is True


# ---- #5 input truncation ------------------------------------------------------
def test_truncate_for_llm():
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(max_input_chars=100))
    big = "H" * 80 + "M" * 100 + "T" * 80
    out = e._truncate_for_llm(big)
    assert len(out) < len(big) and "TRUNCATED" in out
    assert out.startswith("H") and out.rstrip().endswith("T")
    assert e._truncate_for_llm("short") == "short"
    e.settings.analysis.max_input_chars = 0  # disabled
    assert e._truncate_for_llm(big) == big


@pytest.mark.parametrize("position", ["head", "middle", "tail"])
def test_analyze_file_gates_on_complete_context_but_sends_truncated_prompt(tmp_path, position):
    """A detection pattern must reach rule analysis even when prompt truncation would
    omit it. The LLM still receives the bounded head/tail representation."""
    pattern = "db.execSQL(userInput)"
    chunks = {
        "head": pattern + "H" * 280,
        "middle": "H" * 140 + pattern + "T" * 140,
        "tail": "H" * 280 + pattern,
    }
    source = tmp_path / f"{position}.java"
    source.write_text(chunks[position])

    class _Rules:
        def model_dump(self):
            return {"sql_injection": True}

    class _RecordingClient:
        def __init__(self):
            self.inputs = []

        def analyze_code(self, code, _context):
            self.inputs.append(code)
            return '{"is_vulnerable": false, "description": "test verdict"}'

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=100,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_Rules(),
    )
    e.call_graph_builder = None
    e.llm_client = _RecordingClient()
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []
    e.scan_metrics = {"deep_rule_checks": 0}

    results = e.analyze_file(str(source))

    assert [result["rule"] for result in results] == ["sql_injection"]
    assert len(e.llm_client.inputs) == 1
    assert e.scan_metrics["deep_rule_checks"] == 1
    assert e.scan_metrics["deep_rule_checks_accounted"] == 1
    assert e.scan_metrics["deep_rule_checks_completed"] == 1
    assert e.scan_metrics["deep_rule_checks_not_vulnerable"] == 1
    assert e.scan_metrics.get("deep_rule_checks_error", 0) == 0
    assert "TRUNCATED" in e.llm_client.inputs[0]
    assert len(e.llm_client.inputs[0]) < len(chunks[position])
    if position == "middle":
        assert pattern not in e.llm_client.inputs[0]


class _TriageClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    def analyze_code(self, _code, _context):
        if self.error:
            raise self.error
        return self.response


@pytest.mark.parametrize(
    ("response", "expected"),
    [("Yes", ["KeywordOnly.java"]), ("No", [])],
)
def test_risk_triage_valid_yes_and_no(response, expected):
    e = _engine()
    e.llm_client = _TriageClient(response=response)
    e.analysis_errors = []
    assert e.identify_risky_chunks({"KeywordOnly.java": "handles attacker input"}) == expected
    assert e.analysis_errors == []


@pytest.mark.parametrize(
    ("response", "error", "reason"),
    [
        ("", None, "empty"),
        ("maybe", None, "unparseable"),
        (None, TimeoutError("late"), "timeout"),
        (None, RuntimeError("boom"), "exception"),
    ],
)
def test_risk_triage_failure_is_recorded_and_fail_open(response, error, reason):
    e = _engine()
    e.llm_client = _TriageClient(response=response, error=error)
    e.analysis_errors = []
    assert e.identify_risky_chunks({"KeywordOnly.java": "handles attacker input"}) == ["KeywordOnly.java"]
    assert e.analysis_errors[0]["stage"] == "risk_triage"
    assert e.analysis_errors[0]["status"] == "Unanalyzed"
    assert e.analysis_errors[0]["reason"] == reason


def test_keyword_only_candidate_reaches_deep_scan_after_negative_triage():
    """A coarse triage 'No' may lower priority but cannot delete a scoped candidate."""
    candidates = ["Risky.java", "Pattern.java", "KeywordOnly.java"]
    selected = Engine._select_deep_scan_targets(
        candidates, llm_risky=["Risky.java"], pattern_risky=["Pattern.java"]
    )
    assert selected == candidates


@pytest.mark.parametrize(
    ("response", "error"),
    [
        ("Yes", None),
        ("No", None),
        ("", None),
        (None, TimeoutError("late")),
        (None, RuntimeError("boom")),
    ],
)
def test_legacy_triage_outcomes_never_change_deep_membership(response, error):
    candidates = ["KeywordOnly.java", "Pattern.java", "Other.java"]
    e = _engine()
    e.llm_client = _TriageClient(response=response, error=error)
    e.analysis_errors = []
    summaries = {"KeywordOnly.java": "attacker controlled input"}

    risky = e.identify_risky_chunks(summaries)
    selected = e._select_deep_scan_targets(
        candidates, risky, ["Pattern.java"]
    )

    assert set(selected) == set(candidates)
    assert len(selected) == len(candidates)


def test_optimized_pattern_priority_keeps_every_candidate():
    candidates = ["KeywordOnly.java", "Pattern.java", "Other.java"]
    selected = Engine._select_deep_scan_targets(
        candidates, llm_risky=[], pattern_risky=["Pattern.java"]
    )

    assert selected == ["Pattern.java", "KeywordOnly.java", "Other.java"]
    assert set(selected) == set(candidates)


@pytest.mark.parametrize(
    ("response", "error", "reason"),
    [("", None, "empty"), (None, TimeoutError("late"), "timeout"), (None, RuntimeError("boom"), "exception")],
)
def test_summarization_failure_is_recorded_without_dropping_file(tmp_path, response, error, reason):
    source = tmp_path / "KeywordOnly.java"
    source.write_text("String attackerInput = getIntent().getStringExtra(\"q\");")
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(max_input_chars=1000))
    e.llm_client = _TriageClient(response=response, error=error)
    e.analysis_errors = []

    summaries = e.summarize_chunks(str(tmp_path), file_list=[str(source)])

    assert str(source) in summaries
    assert summaries[str(source)] == ""
    assert e.analysis_errors[0]["stage"] == "summarization"
    assert e.analysis_errors[0]["status"] == "Unanalyzed"
    assert e.analysis_errors[0]["reason"] == reason


def test_llm_stage_call_metrics_are_passive_and_count_attempts(tmp_path):
    source = tmp_path / "Candidate.java"
    source.write_text("class Candidate {}")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('<manifest package="com.example"/>')

    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(max_input_chars=1000))
    e.analysis_errors = []
    e.scan_metrics = {
        "summarization_calls": 0,
        "risk_triage_calls": 0,
        "app_summary_calls": 0,
        "attack_surface_calls": 0,
        "triage_yes": 0,
    }
    e.llm_client = _TriageClient(response="summary")
    summaries = e.summarize_chunks(str(tmp_path), file_list=[str(source)])
    e.llm_client.response = "yes"
    assert e.identify_risky_chunks(summaries) == [str(source)]
    e.llm_client.response = '{"is_vulnerable": false}'
    assert e.summarize_app(str(manifest), summaries)
    assert isinstance(e.generate_attack_surface_map(str(manifest), summaries), dict)

    assert e.scan_metrics == {
        "summarization_calls": 1,
        "risk_triage_calls": 1,
        "app_summary_calls": 1,
        "attack_surface_calls": 1,
        "triage_yes": 1,
    }


def test_stage_timer_failure_does_not_change_pipeline_state(monkeypatch):
    e = _engine()
    e.scan_metrics = {"candidate_collection_seconds": 7.0}
    monkeypatch.setattr("core.engine.time.monotonic", lambda: (_ for _ in ()).throw(RuntimeError("clock")))

    started = e._metric_timer_start()
    e._metric_record_duration("candidate_collection_seconds", started)

    assert started is None
    assert e.scan_metrics == {"candidate_collection_seconds": 7.0}


def _summary_test_engine(client):
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(max_input_chars=1000))
    e.llm_client = client
    e.analysis_errors = []
    e.scan_metrics = {"summarization_calls": 0}
    return e


def test_parallel_summarization_is_concurrent_faster_and_ordered(tmp_path):
    import threading
    import time

    files = []
    for index in range(8):
        path = tmp_path / f"Candidate{index}.java"
        path.write_text(f"unique-content-{index}")
        files.append(str(path))

    class _SlowSummaryClient:
        def __init__(self):
            self.active = 0
            self.max_active = 0
            self.lock = threading.Lock()

        def analyze_code(self, code, _context):
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                time.sleep(0.03)
                return "summary:" + code
            finally:
                with self.lock:
                    self.active -= 1

    serial_client = _SlowSummaryClient()
    serial_engine = _summary_test_engine(serial_client)
    started = time.monotonic()
    serial = serial_engine.summarize_chunks(
        str(tmp_path), file_list=files, summary_workers=1
    )
    serial_seconds = time.monotonic() - started

    parallel_client = _SlowSummaryClient()
    parallel_engine = _summary_test_engine(parallel_client)
    started = time.monotonic()
    parallel = parallel_engine.summarize_chunks(
        str(tmp_path), file_list=files, summary_workers=4
    )
    parallel_seconds = time.monotonic() - started

    assert list(parallel) == files
    assert parallel == serial
    assert serial_client.max_active == 1
    assert 1 < parallel_client.max_active <= 4
    assert parallel_seconds < serial_seconds * 0.65
    assert parallel_engine.scan_metrics["summarization_calls"] == len(files)


def test_parallel_summary_merge_ignores_completion_order(tmp_path):
    import time

    files = []
    for name, delay in (("slow", "0.03"), ("fast", "0.00"), ("medium", "0.01")):
        path = tmp_path / f"{name}.java"
        path.write_text(delay)
        files.append(str(path))

    class _OutOfOrderClient:
        def analyze_code(self, code, _context):
            time.sleep(float(code))
            return "summary:" + code

    e = _summary_test_engine(_OutOfOrderClient())
    summaries = e.summarize_chunks(str(tmp_path), file_list=files, summary_workers=3)

    assert list(summaries) == files
    assert list(summaries.values()) == ["summary:0.03", "summary:0.00", "summary:0.01"]


def test_parallel_summarization_keeps_smali_chunk_order(tmp_path):
    smali = tmp_path / "Multi.smali"
    smali.write_text(
        ".class public Lfirst/Class;\n# FIRST\n"
        ".class public Lsecond/Class;\n# SECOND\n"
    )
    other = tmp_path / "Other.java"
    other.write_text("class Other {}")

    class _ChunkClient:
        def analyze_code(self, code, _context):
            if "FIRST" in code:
                return "summary-first"
            if "SECOND" in code:
                return "summary-second"
            return "summary-other"

    e = _summary_test_engine(_ChunkClient())
    summaries = e.summarize_chunks(
        str(tmp_path), file_list=[str(smali), str(other)], summary_workers=2
    )

    assert list(summaries) == [str(smali), str(other)]
    assert summaries[str(smali)] == "summary-first\nsummary-second"
    assert e.scan_metrics["summarization_calls"] == 3


@pytest.mark.parametrize("batch_size", [2, 4, 8])
def test_summary_batch_sizes_reduce_calls_and_preserve_order(tmp_path, batch_size):
    import json

    files = []
    for index in range(8):
        path = tmp_path / f"Candidate{index}.java"
        path.write_text(f"content-{index}")
        files.append(str(path))

    class _StrictBatchClient:
        def __init__(self):
            self.batch_ids = []

        def analyze_code(self, payload, context):
            assert "BATCH OUTPUT CONTRACT" in context["vuln_prompt"]
            items = json.loads(payload)["items"]
            self.batch_ids.extend(item["id"] for item in items)
            return json.dumps({
                item["id"]: "summary:" + item["code"] for item in items
            })

    client = _StrictBatchClient()
    e = _summary_test_engine(client)
    summaries = e.summarize_chunks(
        str(tmp_path),
        file_list=files,
        summary_workers=2,
        summary_batch_size=batch_size,
    )

    expected_calls = (len(files) + batch_size - 1) // batch_size
    assert list(summaries) == files
    assert list(summaries.values()) == [f"summary:content-{i}" for i in range(8)]
    assert len(client.batch_ids) == len(set(client.batch_ids)) == len(files)
    assert all(identifier.startswith("summary_") for identifier in client.batch_ids)
    assert e.scan_metrics["summarization_calls"] == expected_calls
    assert e.scan_metrics["summary_batch_requests"] == expected_calls
    assert e.scan_metrics["summary_batch_items"] == len(files)
    assert e.scan_metrics["summary_batch_valid_items"] == len(files)
    assert e.scan_metrics["summary_batch_fallback_items"] == 0
    assert e.scan_metrics["summary_batch_failures"] == 0
    assert e.analysis_errors == []


def test_summary_batch_ids_are_stable_and_path_aware(tmp_path):
    first = tmp_path / "one" / "Same.java"
    second = tmp_path / "two" / "Same.java"
    assert Engine._summary_unit_id(0, str(first), 0) == Engine._summary_unit_id(
        0, str(first), 0
    )
    assert Engine._summary_unit_id(0, str(first), 0) != Engine._summary_unit_id(
        0, str(second), 0
    )
    assert Engine._summary_unit_id(0, str(first), 0) != Engine._summary_unit_id(
        0, str(first), 1
    )


def test_summary_batch_trailing_singleton_uses_individual_contract(tmp_path):
    source = tmp_path / "Only.java"
    source.write_text("only-content")

    class _IndividualOnlyClient:
        def analyze_code(self, code, context):
            assert "BATCH OUTPUT CONTRACT" not in context["vuln_prompt"]
            return "individual:" + code

    e = _summary_test_engine(_IndividualOnlyClient())
    summaries = e.summarize_chunks(
        str(tmp_path),
        file_list=[str(source)],
        summary_workers=2,
        summary_batch_size=8,
    )

    assert summaries == {str(source): "individual:only-content"}
    assert e.scan_metrics["summarization_calls"] == 1
    assert e.scan_metrics["summary_batch_requests"] == 0
    assert e.scan_metrics["summary_batch_items"] == 0


def test_partial_summary_batch_retries_only_missing_item(tmp_path):
    import json

    files = []
    for index in range(3):
        path = tmp_path / f"Candidate{index}.java"
        path.write_text(f"content-{index}")
        files.append(str(path))

    class _PartialClient:
        def __init__(self):
            self.batch_calls = 0
            self.individual_calls = []

        def analyze_code(self, code, context):
            if "BATCH OUTPUT CONTRACT" in context["vuln_prompt"]:
                self.batch_calls += 1
                items = json.loads(code)["items"]
                return json.dumps({
                    item["id"]: "batch:" + item["code"] for item in items[:2]
                })
            self.individual_calls.append(code)
            return "individual:" + code

    client = _PartialClient()
    e = _summary_test_engine(client)
    summaries = e.summarize_chunks(
        str(tmp_path), file_list=files, summary_workers=1, summary_batch_size=3
    )

    assert list(summaries.values()) == [
        "batch:content-0", "batch:content-1", "individual:content-2"
    ]
    assert client.batch_calls == 1
    assert client.individual_calls == ["content-2"]
    assert e.scan_metrics["summarization_calls"] == 2
    assert e.scan_metrics["summary_batch_valid_items"] == 2
    assert e.scan_metrics["summary_batch_fallback_items"] == 1
    assert e.scan_metrics["summary_batch_failures"] == 1
    assert e.analysis_errors == []


def test_partial_summary_batch_is_invalidated_but_individual_fallback_is_cached(tmp_path):
    import json
    import os

    first = tmp_path / "First.java"
    second = tmp_path / "Second.java"
    first.write_text("first-content")
    second.write_text("second-content")
    files = [str(first), str(second)]

    class _AlwaysPartialClient:
        def __init__(self):
            self.batch_calls = 0
            self.individual_calls = 0
            self.last_batch = None

        def analyze_code(self, code, context):
            if "BATCH OUTPUT CONTRACT" in context["vuln_prompt"]:
                self.batch_calls += 1
                self.last_batch = (code, dict(context))
                items = json.loads(code)["items"]
                return json.dumps({items[0]["id"]: "batch-first"})
            self.individual_calls += 1
            return "individual:" + code

    raw = _AlwaysPartialClient()
    cached = CachedLLMClient(
        raw, str(tmp_path / "cache"), model="fixture", enabled=True
    )
    e = _summary_test_engine(cached)

    first_run = e.summarize_chunks(
        str(tmp_path), file_list=files, summary_workers=1, summary_batch_size=2
    )
    batch_code, batch_context = raw.last_batch
    invalid_batch_path = cached._path(cached._key(batch_code, batch_context))
    assert not os.path.exists(invalid_batch_path)

    second_run = e.summarize_chunks(
        str(tmp_path), file_list=files, summary_workers=1, summary_batch_size=2
    )
    assert first_run == second_run == {
        str(first): "batch-first",
        str(second): "individual:second-content",
    }
    # Invalid batch is retried; the valid individual fallback keeps its old cache key.
    assert raw.batch_calls == 2
    assert raw.individual_calls == 1
    assert cached.cache_stats()["hits"] == 1


@pytest.mark.parametrize("batch_failure", ["empty", "invalid", "timeout"])
def test_failed_summary_batch_falls_back_all_items(tmp_path, batch_failure):
    import json

    files = []
    for index in range(2):
        path = tmp_path / f"Candidate{index}.java"
        path.write_text(f"content-{index}")
        files.append(str(path))

    class _FailedBatchClient:
        def __init__(self):
            self.individual = 0

        def analyze_code(self, code, context):
            if "BATCH OUTPUT CONTRACT" in context["vuln_prompt"]:
                if batch_failure == "empty":
                    return ""
                if batch_failure == "invalid":
                    return json.dumps({"unknown_id": "wrong mapping"})
                raise TimeoutError("batch timeout")
            self.individual += 1
            return "fallback:" + code

    client = _FailedBatchClient()
    e = _summary_test_engine(client)
    summaries = e.summarize_chunks(
        str(tmp_path), file_list=files, summary_workers=2, summary_batch_size=2
    )

    assert list(summaries.values()) == ["fallback:content-0", "fallback:content-1"]
    assert client.individual == 2
    assert e.scan_metrics["summarization_calls"] == 3
    assert e.scan_metrics["summary_batch_valid_items"] == 0
    assert e.scan_metrics["summary_batch_fallback_items"] == 2
    assert e.scan_metrics["summary_batch_failures"] == 1
    assert e.analysis_errors == []


def test_batched_smali_preserves_chunk_order(tmp_path):
    import json

    smali = tmp_path / "Multi.smali"
    smali.write_text(
        ".class public Lfirst/Class;\n# FIRST\n"
        ".class public Lsecond/Class;\n# SECOND\n"
    )
    other = tmp_path / "Other.java"
    other.write_text("class Other {}")

    class _ChunkBatchClient:
        def analyze_code(self, payload, context):
            if "BATCH OUTPUT CONTRACT" not in context["vuln_prompt"]:
                assert payload == "class Other {}"
                return "summary-other"
            items = json.loads(payload)["items"]
            output = {}
            for item in items:
                if "FIRST" in item["code"]:
                    output[item["id"]] = "summary-first"
                elif "SECOND" in item["code"]:
                    output[item["id"]] = "summary-second"
                else:
                    output[item["id"]] = "summary-other"
            return json.dumps(output)

    e = _summary_test_engine(_ChunkBatchClient())
    summaries = e.summarize_chunks(
        str(tmp_path),
        file_list=[str(smali), str(other)],
        summary_workers=2,
        summary_batch_size=2,
    )

    assert list(summaries) == [str(smali), str(other)]
    assert summaries[str(smali)] == "summary-first\nsummary-second"
    assert summaries[str(other)] == "summary-other"
    assert e.scan_metrics["summarization_calls"] == 2
    assert e.scan_metrics["summary_batch_items"] == 2


def test_parallel_summarization_deduplicates_identical_cache_keys(tmp_path):
    import threading
    import time

    first = tmp_path / "First.java"
    second = tmp_path / "Second.java"
    first.write_text("identical content")
    second.write_text("identical content")

    class _SlowCountingClient:
        def __init__(self):
            self.calls = 0
            self.lock = threading.Lock()

        def analyze_code(self, code, _context):
            with self.lock:
                self.calls += 1
            time.sleep(0.02)
            return "summary:" + code

    raw_client = _SlowCountingClient()
    cached = CachedLLMClient(
        raw_client, str(tmp_path / "cache"), model="fixture", enabled=True
    )
    e = _summary_test_engine(cached)
    summaries = e.summarize_chunks(
        str(tmp_path), file_list=[str(first), str(second)], summary_workers=2
    )

    assert list(summaries) == [str(first), str(second)]
    assert summaries[str(first)] == summaries[str(second)] == "summary:identical content"
    assert raw_client.calls == 1
    assert cached.cache_stats()["misses"] == 1
    assert cached.cache_stats()["hits"] == 1
    # Metrics count scheduled LLM-client attempts, including cache hits.
    assert e.scan_metrics["summarization_calls"] == 2


def test_parallel_summary_failures_are_merged_in_input_order_and_fail_open(tmp_path):
    import threading

    missing = tmp_path / "01-missing.java"
    empty = tmp_path / "02-empty-response.java"
    timeout = tmp_path / "03-timeout.java"
    valid = tmp_path / "04-valid.java"
    empty.write_text("empty")
    timeout.write_text("timeout")
    valid.write_text("valid")
    files = [str(missing), str(empty), str(timeout), str(valid)]

    class _FailureClient:
        def analyze_code(self, code, _context):
            if code == "empty":
                return ""
            if code == "timeout":
                raise TimeoutError("fixture timeout")
            return "summary-valid"

    e = _summary_test_engine(_FailureClient())
    record_threads = []
    original_record = e._record_pipeline_error

    def record_on_main(*args, **kwargs):
        record_threads.append(threading.get_ident())
        return original_record(*args, **kwargs)

    e._record_pipeline_error = record_on_main
    main_thread = threading.get_ident()
    summaries = e.summarize_chunks(str(tmp_path), file_list=files, summary_workers=4)

    assert list(summaries) == files
    assert summaries == {
        str(missing): "",
        str(empty): "",
        str(timeout): "",
        str(valid): "summary-valid",
    }
    assert [error["reason"] for error in e.analysis_errors] == [
        "file_read_error", "empty", "timeout"
    ]
    assert record_threads == [main_thread, main_thread, main_thread]
    assert e.scan_metrics["summarization_calls"] == 3
    assert Engine._select_deep_scan_targets(files, [], []) == files


def test_unexpected_parallel_worker_exception_is_fail_open(tmp_path, monkeypatch):
    first = tmp_path / "First.java"
    second = tmp_path / "Second.java"
    first.write_text("first")
    second.write_text("second")
    e = _summary_test_engine(_TriageClient(response="summary"))
    original_worker = e._summarize_file

    def worker(path, prompt):
        if path == str(first):
            raise RuntimeError("unexpected worker failure")
        return original_worker(path, prompt)

    monkeypatch.setattr(e, "_summarize_file", worker)
    summaries = e.summarize_chunks(
        str(tmp_path), file_list=[str(first), str(second)], summary_workers=2
    )

    assert list(summaries) == [str(first), str(second)]
    assert summaries[str(first)] == ""
    assert summaries[str(second)] == "summary"
    assert e.analysis_errors[0]["stage"] == "summarization"
    assert e.analysis_errors[0]["reason"] == "exception"


def test_parallel_summary_does_not_swallow_keyboard_interrupt(tmp_path, monkeypatch):
    source = tmp_path / "Candidate.java"
    source.write_text("candidate")
    e = _summary_test_engine(_TriageClient(response="summary"))
    monkeypatch.setattr(
        e,
        "_summarize_file",
        lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    with pytest.raises(KeyboardInterrupt):
        e.summarize_chunks(
            str(tmp_path), file_list=[str(source)], summary_workers=2
        )


# ---- #2 / Ollama-JSON: failure & parse handling -------------------------------
def test_is_failed_response():
    e = _engine()
    assert e._is_failed_response("") is True
    assert e._is_failed_response("   ") is True
    assert e._is_failed_response(None) is True
    assert e._is_failed_response('{"x": 1}') is False


def test_parse_prose_is_flagged_not_clean():
    e = _engine()
    parsed = e._parse_llm_response("Yes, there is a SQL injection vulnerability here.")
    assert parsed.get("_parse_failed") is True
    assert parsed.get("is_vulnerable") is False


def test_parse_valid_json():
    e = _engine()
    ok = e._parse_llm_response('{"is_vulnerable": true, "severity": "High"}')
    assert ok["is_vulnerable"] is True
    assert "_parse_failed" not in ok


def test_parse_non_object_json_is_flagged_not_clean():
    e = _engine()
    parsed = e._parse_llm_response('["not", "an", "object"]')
    assert parsed["_parse_failed"] is True


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"is_vulnerable": True}, "Vulnerable"),
        ({"is_vulnerable": False}, "Not Vulnerable"),
        ({"is_vulnerable": "true"}, "Error"),
        ({"is_vulnerable": "false"}, "Error"),
        ({"is_vulnerable": None}, "Error"),
        ({"is_vulnerable": 1}, "Error"),
        ({"is_vulnerable": 0}, "Error"),
        ({}, "Error"),
        ([], "Error"),
    ],
)
def test_get_status_requires_a_real_json_boolean(result, expected):
    e = _engine()
    assert e.get_status(result) == expected


def test_invalid_verdict_becomes_error_and_keeps_raw_response(tmp_path):
    source = tmp_path / "InvalidVerdict.java"
    source.write_text('db.execSQL("SELECT " + attackerInput);')

    class _Rules:
        def model_dump(self):
            return {"sql_injection": True}

    raw = '{"is_vulnerable": "false", "description": "wrong field type"}'
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_Rules(),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(response=raw)
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    results = e.analyze_file(str(source))

    assert [(result["rule"], result["status"]) for result in results] == [
        ("sql_injection", "Error")
    ]
    assert results[0]["result"]["status_detail"] == "UNANALYZED"
    assert results[0]["result"]["is_vulnerable"] is None
    assert results[0]["result"]["raw_response"] == raw
    assert e.analysis_errors == [{
        "file": str(source),
        "rule": "sql_injection",
        "stage": "rule_analysis",
        "status": "Unanalyzed",
        "reason": "invalid_verdict",
        "raw_response": raw,
    }]


def test_rule_exception_is_unanalyzed_and_does_not_stop_later_rules(tmp_path):
    source = tmp_path / "TwoSignals.java"
    source.write_text(
        'db.execSQL("SELECT " + attackerInput); '
        'new File(baseDir, attackerName);'
    )

    class _Rules:
        def model_dump(self):
            return {"sql_injection": True, "path_traversal": True}

    class _SequenceClient:
        def __init__(self):
            self.calls = 0

        def analyze_code(self, _code, _context):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("fixture timeout")
            return '{"is_vulnerable": true, "description": "second rule still ran"}'

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_Rules(),
    )
    e.call_graph_builder = None
    e.llm_client = _SequenceClient()
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []
    e.scan_metrics = {"deep_rule_checks": 0}

    results = e.analyze_file(str(source))

    assert [(result["rule"], result["status"]) for result in results] == [
        ("sql_injection", "Error"),
        ("path_traversal", "Vulnerable"),
    ]
    assert e.llm_client.calls == 2
    assert e.scan_metrics["deep_rule_checks"] == 2
    assert e.scan_metrics["deep_rule_checks_accounted"] == 2
    assert e.scan_metrics["deep_rule_checks_completed"] == 1
    assert e.scan_metrics["deep_rule_checks_vulnerable"] == 1
    assert e.scan_metrics.get("deep_rule_checks_not_vulnerable", 0) == 0
    assert e.scan_metrics["deep_rule_checks_error"] == 1
    assert e.analysis_errors[0]["stage"] == "rule_analysis"
    assert e.analysis_errors[0]["reason"] == "timeout"
    assert e.analysis_errors[0]["status"] == "Unanalyzed"


def test_parse_fenced_json_with_nested_braces_in_evidence():
    e = _engine()
    raw = '```json\n{"is_vulnerable": true, "evidence": "if (a) {b();}"}\n```'
    parsed = e._parse_llm_response(raw)
    assert parsed["is_vulnerable"] is True
    assert "{" in parsed["evidence"]  # nested braces inside a string value survived


# ---- #4 response cache --------------------------------------------------------
class _FakeClient:
    def __init__(self):
        self.calls = 0

    def analyze_code(self, code, ctx):
        self.calls += 1
        return "" if code == "FAIL" else f"R:{code}"

    def other(self):
        return "delegated"


def test_cache_hit_and_no_cache_of_failures(tmp_path):
    fake = _FakeClient()
    cc = CachedLLMClient(fake, str(tmp_path / "c"), model="m", enabled=True)
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    assert cc.analyze_code("x", ctx) == cc.analyze_code("x", ctx)
    assert fake.calls == 1  # second call served from cache
    # empty responses must NOT be cached -> retried each time
    cc.analyze_code("FAIL", ctx)
    cc.analyze_code("FAIL", ctx)
    assert fake.calls == 3
    # unknown attributes delegate to the wrapped client
    assert cc.other() == "delegated"


def test_cache_io_failures_are_exposed_to_engine_audit_trail(tmp_path):
    fake = _FakeClient()
    cc = CachedLLMClient(fake, str(tmp_path / "cache"), model="m", enabled=True)
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "Finding.java"}
    key_path = cc._path(cc._key("x", ctx))
    # A directory at the expected cache-file path forces both read and write to fail,
    # while the underlying LLM call still succeeds.
    import os
    os.makedirs(key_path)

    assert cc.analyze_code("x", ctx) == "R:x"
    assert [error["operation"] for error in cc.cache_stats()["errors"]] == ["read", "write"]

    e = _engine()
    e.llm_client = cc
    e.exploit_llm_client = cc
    e.analysis_errors = []
    e.apk_name = "fixture.apk"
    e._collect_cache_errors()

    assert [error["stage"] for error in e.analysis_errors] == ["cache", "cache"]
    assert [error["status"] for error in e.analysis_errors] == ["Error", "Error"]


def test_cache_resume_across_new_wrapper(tmp_path):
    d = str(tmp_path / "c")
    fake1 = _FakeClient()
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    CachedLLMClient(fake1, d, model="m", enabled=True).analyze_code("x", ctx)
    fake2 = _FakeClient()
    assert CachedLLMClient(fake2, d, model="m", enabled=True).analyze_code("x", ctx) == "R:x"
    assert fake2.calls == 0  # served from disk cache written by the first wrapper


def test_cache_key_includes_client_fingerprint(tmp_path):
    """Regression: settings that change the ANSWER but never appear in the prompt must be
    part of the cache key. Confirmed live before the fix: a run at reasoning_effort=low
    followed by one at xhigh hit the cached low answer and never called the model at
    xhigh — silently returning shallower analysis than the user asked for."""
    class _Fp:
        def __init__(self, fp):
            self.fp = fp
            self.calls = 0

        def cache_fingerprint(self):
            return self.fp

        def analyze_code(self, code, ctx):
            self.calls += 1
            return f"R:{self.fp}"

    d = str(tmp_path / "c")
    ctx = {"system_prompt": "s", "vuln_prompt": "v"}
    low, high = _Fp("reasoning_effort=low"), _Fp("reasoning_effort=xhigh")
    assert CachedLLMClient(low, d, model="m", enabled=True).analyze_code("x", ctx) == "R:reasoning_effort=low"
    # Different fingerprint -> must MISS and actually call the client, not reuse `low`.
    assert CachedLLMClient(high, d, model="m", enabled=True).analyze_code("x", ctx) == "R:reasoning_effort=xhigh"
    assert high.calls == 1
    # Same fingerprint -> still hits, i.e. caching is not simply broken.
    again = _Fp("reasoning_effort=low")
    assert CachedLLMClient(again, d, model="m", enabled=True).analyze_code("x", ctx) == "R:reasoning_effort=low"
    assert again.calls == 0


def test_empty_fingerprint_keeps_legacy_cache_keys(tmp_path):
    """An empty fingerprint must be skipped entirely, so upgrading does not invalidate
    the on-disk cache of providers that don't expose one (every HTTP client today)."""
    import hashlib

    def legacy_key(model, ctx, code):
        h = hashlib.sha256()
        for part in (model, ctx.get("system_prompt", ""), ctx.get("vuln_prompt", ""), code):
            h.update(part.encode("utf-8", errors="replace"))
            h.update(b"\x00")
        return h.hexdigest()

    ctx = {"system_prompt": "s", "vuln_prompt": "v"}
    d = str(tmp_path / "c")
    # no cache_fingerprint at all (all existing clients + test fakes)
    assert CachedLLMClient(_FakeClient(), d, model="m", enabled=True)._key("x", ctx) == legacy_key("m", ctx, "x")

    class _Empty(_FakeClient):
        def cache_fingerprint(self):
            return ""

    assert CachedLLMClient(_Empty(), d, model="m", enabled=True)._key("x", ctx) == legacy_key("m", ctx, "x")


def test_fingerprint_failure_is_soft(tmp_path):
    """A client whose fingerprint raises must not take the scan down with it."""
    class _Boom(_FakeClient):
        def cache_fingerprint(self):
            raise RuntimeError("boom")

    cc = CachedLLMClient(_Boom(), str(tmp_path / "c"), model="m", enabled=True)
    assert cc.analyze_code("x", {"system_prompt": "s", "vuln_prompt": "v"}) == "R:x"


def test_codex_fingerprint_tracks_reasoning_effort():
    """Unpinned effort -> empty fingerprint (the effective value lives in
    ~/.codex/config.toml and is invisible here), pinned -> it keys the cache."""
    assert _codex().cache_fingerprint() == ""
    assert _codex(reasoning_effort="xhigh").cache_fingerprint() == "reasoning_effort=xhigh"
    assert _codex(reasoning_effort="low").cache_fingerprint() != _codex(reasoning_effort="high").cache_fingerprint()


def test_cache_disabled_bypasses(tmp_path):
    fake = _FakeClient()
    cc = CachedLLMClient(fake, str(tmp_path / "c"), model="m", enabled=False)
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    cc.analyze_code("x", ctx)
    cc.analyze_code("x", ctx)
    assert fake.calls == 2


def test_concurrent_same_key_cache_request_is_deduplicated_and_atomic(tmp_path):
    import concurrent.futures
    import threading
    import time

    class _SlowClient:
        def __init__(self):
            self.calls = 0
            self.lock = threading.Lock()

        def analyze_code(self, code, _ctx):
            with self.lock:
                self.calls += 1
            time.sleep(0.02)
            return "complete:" + code

    fake = _SlowClient()
    cache_dir = tmp_path / "cache"
    cc = CachedLLMClient(fake, str(cache_dir), model="m", enabled=True)
    ctx = {"system_prompt": "s", "vuln_prompt": "v", "file_path": "F"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: cc.analyze_code("x", ctx), range(8)))

    assert results == ["complete:x"] * 8
    assert fake.calls == 1
    assert cc.cache_stats()["misses"] == 1
    assert cc.cache_stats()["hits"] == 7
    assert list(cache_dir.glob("*.tmp")) == []
    assert open(cc._path(cc._key("x", ctx)), encoding="utf-8").read() == "complete:x"


def test_concurrent_empty_cache_response_is_never_persisted(tmp_path):
    import concurrent.futures
    import threading

    class _EmptyClient:
        def __init__(self):
            self.calls = 0
            self.lock = threading.Lock()

        def analyze_code(self, _code, _ctx):
            with self.lock:
                self.calls += 1
            return ""

    fake = _EmptyClient()
    cc = CachedLLMClient(fake, str(tmp_path / "cache"), model="m", enabled=True)
    ctx = {"system_prompt": "s", "vuln_prompt": "v"}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _: cc.analyze_code("FAIL", ctx), range(4)))

    assert results == [""] * 4
    assert fake.calls == 4
    assert cc.cache_stats()["misses"] == 4
    assert not (tmp_path / "cache" / f"{cc._key('FAIL', ctx)}.txt").exists()


def test_same_key_lock_is_released_after_client_exception(tmp_path):
    class _FlakyClient:
        def __init__(self):
            self.calls = 0

        def analyze_code(self, code, _ctx):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("first request timed out")
            return "recovered:" + code

    fake = _FlakyClient()
    cc = CachedLLMClient(fake, str(tmp_path / "cache"), model="m", enabled=True)
    ctx = {"system_prompt": "s", "vuln_prompt": "v"}

    with pytest.raises(TimeoutError):
        cc.analyze_code("x", ctx)
    assert cc.analyze_code("x", ctx) == "recovered:x"
    assert fake.calls == 2


# ---- cross-language call graph mapping ----------------------------------------
def _finding(file, rule, vuln, sev="High", status="Vulnerable"):
    return {"file": file, "rule": rule, "vulnerability": vuln, "status": status,
            "result": {"severity": sev, "description": f"{vuln} detail"}}


def test_dedupe_family_merge():
    """[#E] WebView-family findings on the same file collapse to one + also_detected_by."""
    e = _engine()
    out = e._dedupe_findings([
        _finding("W.java", "webview_xss", "WebView XSS", "High"),
        _finding("W.java", "insecure_webview", "Insecure WebView", "Medium"),
        _finding("W.java", "webview_file_access", "WebView File Access", "Low"),
    ])
    assert len(out) == 1
    assert out[0]["rule"] == "webview_xss"  # highest severity kept as primary
    also = {a["rule"] for a in out[0]["also_detected_by"]}
    assert also == {"insecure_webview", "webview_file_access"}


def test_dedupe_generic_fold_when_specific_present():
    """[#E] universal_logic_flaw folds into a specific finding on the same file (kept, not dropped)."""
    e = _engine()
    out = e._dedupe_findings([
        _finding("C.java", "biometric_bypass", "Biometric", "High"),
        _finding("C.java", "universal_logic_flaw", "Conceptual Logic Flaw Detection", "Medium"),
    ])
    top = {r["rule"] for r in out}
    assert "universal_logic_flaw" not in top and "biometric_bypass" in top
    host = next(r for r in out if r["rule"] == "biometric_bypass")
    folded = [a for a in host["also_detected_by"] if a["rule"] == "universal_logic_flaw"]
    assert folded and folded[0]["description"]  # detail preserved


def test_dedupe_generic_standalone_kept():
    """[#E] universal_logic_flaw alone on a file stays as a real finding."""
    e = _engine()
    out = e._dedupe_findings([_finding("X.java", "universal_logic_flaw", "Conceptual Logic Flaw Detection")])
    assert len(out) == 1 and out[0]["rule"] == "universal_logic_flaw"


def test_dedupe_keeps_distinct_files_and_passes_through_non_vulnerable():
    e = _engine()
    out = e._dedupe_findings([
        _finding("A.java", "webview_xss", "WebView XSS"),
        _finding("B.java", "insecure_webview", "Insecure WebView"),
        _finding("A.java", "sql_injection", "SQL Injection", status="Not Vulnerable"),
        _finding("A.java", "path_traversal", "Path Traversal", status="Error"),
    ])
    # 2 distinct-file vulnerable (not merged) + 2 passthrough
    assert len(out) == 4


def test_json_only_suffix_is_format_safe():
    """[#C] The appended JSON-only suffix must be brace-free (vuln_prompt goes through str.format())."""
    from core.engine import JSON_ONLY_SUFFIX
    assert "{" not in JSON_ONLY_SUFFIX and "}" not in JSON_ONLY_SUFFIX
    assert "JSON" in JSON_ONLY_SUFFIX
    # sanity: a rule prompt + suffix still formats without KeyError
    ("Analyze {code_snippet} at {file_path}" + JSON_ONLY_SUFFIX).format(code_snippet="x", file_path="y")


def test_manifest_rules_are_single_source_of_truth():
    """Regression: strandhogg is manifest-only. It previously leaked into the code
    deep-scan (missing from the exclusion list) and false-positived on every risky
    Java file. MANIFEST_RULES is now the single source used by both paths."""
    from core.engine import MANIFEST_RULES
    from core.config_loader import RulesSettings
    valid = set(RulesSettings.model_fields)
    assert "strandhogg" in MANIFEST_RULES
    for r in MANIFEST_RULES:
        assert r in valid, f"MANIFEST_RULES has unknown rule: {r}"


def test_dedicated_pass_rules_excluded_from_code_scan():
    """Regression: rules with their own pass must NOT run in the code deep-scan.
    hardcoded_secrets_xml (strings.xml-only) leaked onto .java files and false-positived."""
    from core.engine import MANIFEST_RULES, DEDICATED_PASS_RULES
    from core.config_loader import RulesSettings
    valid = set(RulesSettings.model_fields)
    assert "hardcoded_secrets_xml" in DEDICATED_PASS_RULES
    assert set(MANIFEST_RULES) <= DEDICATED_PASS_RULES
    for r in DEDICATED_PASS_RULES:
        assert r in valid, f"DEDICATED_PASS_RULES has unknown rule: {r}"


def test_pattern_matched_files_rescues_every_scoped_namespace(tmp_path):
    """Pattern rescue trusts the already-scoped input instead of imposing a second,
    exact-package gate that loses sibling and obfuscated app namespaces."""
    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(scan_libraries=False))
    pkg = tmp_path / "sources" / "com" / "dlh" / "vulnerapp"
    sibling = tmp_path / "sources" / "com" / "vendor" / "feature"
    obfuscated = tmp_path / "sources" / "x" / "y" / "a"
    lib = tmp_path / "sources" / "kotlin" / "coroutines"
    pkg.mkdir(parents=True)
    sibling.mkdir(parents=True)
    obfuscated.mkdir(parents=True)
    lib.mkdir(parents=True)
    app_hit = pkg / "ZipSlipActivity.java"
    app_hit.write_text("ZipEntry e = zis.getNextEntry(); new File(dir, e.getName());")
    sibling_hit = sibling / "ArchiveFeature.java"
    sibling_hit.write_text("ZipEntry e = zis.getNextEntry(); new File(dir, e.getName());")
    obfuscated_hit = obfuscated / "A.java"
    obfuscated_hit.write_text("ZipEntry e = zis.getNextEntry(); new File(dir, e.getName());")
    app_miss = pkg / "Boring.java"
    app_miss.write_text("int x = 1;")
    lib_hit = lib / "FastServiceLoader.java"
    lib_hit.write_text("ZipEntry e; e.getName();")
    files = [str(app_hit), str(sibling_hit), str(obfuscated_hit), str(app_miss), str(lib_hit)]
    scoped = [f for f in files if e._is_relevant_file(f, "com.dlh.vulnerapp")]
    patterns = [r"ZipEntry.*(?:\.|->)getName"]
    out = e._pattern_matched_files(scoped, patterns, "com.dlh.vulnerapp")
    assert str(app_hit) in out
    assert str(sibling_hit) in out
    assert str(obfuscated_hit) in out
    assert str(app_miss) not in out
    assert str(lib_hit) not in scoped


def test_scan_libraries_adds_to_standard_candidates_instead_of_replacing_them(tmp_path):
    sources = tmp_path / "sources"
    app = sources / "com" / "example" / "app"
    library = sources / "androidx" / "loader"
    app.mkdir(parents=True)
    library.mkdir(parents=True)
    sql_file = app / "SQLActivity.java"
    library_file = library / "DynamicLoader.java"
    sql_file.write_text('db.execSQL("SELECT * FROM users WHERE id=" + attackerInput);')
    library_file.write_text("DexClassLoader loader = new DexClassLoader(path, out, null, parent);")

    e = _engine()
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(scan_libraries=False))
    standard = e._collect_static_candidates(
        "hybrid",
        str(tmp_path),
        str(sources),
        [],
        [r"execSQL\s*\("],
        True,
    )
    assert standard == [str(sql_file)]

    e.settings.analysis.scan_libraries = True
    with_libraries = e._collect_static_candidates(
        "hybrid",
        str(tmp_path),
        str(sources),
        [],
        [r"execSQL\s*\("],
        True,
    )
    assert set(standard) <= set(with_libraries)
    assert str(sql_file) in with_libraries
    assert str(library_file) in with_libraries


def test_scan_libraries_keeps_first_party_rule_analysis_active(tmp_path):
    source = tmp_path / "sources" / "com" / "example" / "app" / "SQLActivity.java"
    source.parent.mkdir(parents=True)
    source.write_text('db.execSQL("SELECT * FROM users WHERE id=" + attackerInput);')

    class _Rules:
        def model_dump(self):
            return {"sql_injection": True}

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=True,
            generate_exploit=False,
        ),
        rules=_Rules(),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(
        response='{"is_vulnerable": true, "severity": "High", "description": "tainted SQL"}'
    )
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    results = e.analyze_file(str(source))

    assert [(result["rule"], result["status"]) for result in results] == [
        ("sql_injection", "Vulnerable")
    ]


class _SelectableRules:
    def __init__(self, **values):
        self.values = values

    def model_dump(self):
        return dict(self.values)

    def __getattr__(self, name):
        return self.values.get(name, False)


def test_static_only_never_enters_summary_path_when_summary_workers_changes(tmp_path, monkeypatch):
    import json

    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    sources = decompiled / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    candidate = sources / "SQLActivity.java"
    candidate.write_text('db.execSQL("SELECT " + attackerInput);')
    (decompiled / "AndroidManifest.xml").write_text('<manifest package="com.example"/>')

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            filter_mode="static_only",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
            scan_libraries=False,
            max_workers=1,
            summary_workers=32,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    e.masvs_mapping = {}
    e._load_rule_signals = lambda _rules: (["execSQL"], [])
    e._collect_static_candidates = lambda *_args, **_kwargs: [str(candidate)]
    e._is_relevant_file = lambda *_args: True
    e.summarize_chunks = lambda *_args, **_kwargs: pytest.fail(
        "static_only must not summarize candidates"
    )
    e.summarize_app = lambda *_args: "fixture app"
    e.analyze_strings_xml = lambda *_args: []
    e.analyze_manifest = lambda *_args: []
    analyzed = []
    e.analyze_file = lambda path, _rules: analyzed.append(path) or []

    report_path = tmp_path / "static-report.json"
    e.run("fixture.apk", output_file=str(report_path), no_decompile=True)
    report = json.loads(report_path.read_text())

    assert analyzed == [str(candidate)]
    assert report["scan_metrics"]["candidates_raw"] == 1
    assert report["scan_metrics"]["candidates_scoped"] == 1
    assert report["scan_metrics"]["deep_scan_targets"] == 1
    assert report["scan_metrics"]["deep_scan_priority"] == "candidate_order"
    assert report["scan_metrics"]["deep_scan_files_scheduled"] == 1
    assert report["scan_metrics"]["deep_scan_files_completed"] == 1
    assert report["scan_metrics"]["deep_scan_file_accounting_complete"] is True
    assert report["scan_metrics"]["summarization_calls"] == 0
    assert report["scan_metrics"]["risk_triage_calls"] == 0


@pytest.mark.parametrize(
    ("hybrid_risk_triage", "expected_triage_errors"),
    [(True, 1), (False, 0)],
)
def test_hybrid_parallel_summary_failure_still_reaches_deep_scan(
    tmp_path, monkeypatch, hybrid_risk_triage, expected_triage_errors
):
    import json

    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    sources = decompiled / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    candidate = sources / "SQLActivity.java"
    candidate.write_text('db.execSQL("SELECT " + attackerInput);')
    (decompiled / "AndroidManifest.xml").write_text('<manifest package="com.example"/>')

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            filter_mode="hybrid",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
            scan_libraries=False,
            max_workers=1,
            summary_workers=2,
            hybrid_risk_triage=hybrid_risk_triage,
            max_input_chars=1000,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    # Empty summarization is an explicit failure, never a clean verdict or a gate.
    e.llm_client = _TriageClient(response="")
    e.exploit_llm_client = e.llm_client
    e.masvs_mapping = {}
    e._load_summarize_prompt = lambda: "summarize"
    e._load_identify_risk_prompt = lambda: "risk"
    e._load_rule_signals = lambda _rules: (["execSQL"], [r"execSQL\s*\("])
    e._collect_static_candidates = lambda *_args, **_kwargs: [str(candidate)]
    e._is_relevant_file = lambda *_args: True
    e._pattern_matched_files = lambda *_args: [str(candidate)]
    e.analyze_strings_xml = lambda *_args: []
    e.analyze_manifest = lambda *_args: []
    e.summarize_app = lambda *_args: "fixture app"
    analyzed = []
    e.analyze_file = lambda path, _rules: analyzed.append(path) or []

    report_path = tmp_path / "hybrid-error-report.json"
    e.run("fixture.apk", output_file=str(report_path), no_decompile=True)
    report = json.loads(report_path.read_text())

    assert analyzed == [str(candidate)]
    assert report["scan_metrics"]["candidates_scoped"] == 1
    assert report["scan_metrics"]["deep_scan_targets"] == 1
    assert report["scan_metrics"]["summarization_calls"] == 1
    assert report["scan_metrics"]["triage_errors"] == expected_triage_errors
    assert report["scan_metrics"]["risk_triage_calls"] == 0
    assert report["scan_status"] == "CompletedWithErrors"
    error_stages = {error["stage"] for error in report["analysis_errors"]}
    assert "summarization" in error_stages
    if hybrid_risk_triage:
        assert "risk_triage" in error_stages
        assert report["scan_metrics"]["hybrid_risk_triage"] == "legacy_enabled"
    else:
        assert "risk_triage" not in error_stages
        assert report["scan_metrics"]["hybrid_risk_triage"] == "skipped_redundant"


def test_hybrid_triage_off_never_calls_triage_and_prioritizes_without_gating(
    tmp_path, monkeypatch
):
    import json

    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    sources = decompiled / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    keyword = sources / "KeywordOnly.java"
    pattern = sources / "Pattern.java"
    keyword.write_text("keyword candidate")
    pattern.write_text("pattern candidate")
    (decompiled / "AndroidManifest.xml").write_text('<manifest package="com.example"/>')

    class _NoTriageClient:
        def __init__(self):
            self.calls = 0

        def analyze_code(self, code, context):
            if context.get("vuln_prompt") == "risk":
                pytest.fail("optimized hybrid must not call risk triage")
            self.calls += 1
            return "summary:" + code

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            filter_mode="hybrid",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
            scan_libraries=False,
            max_workers=1,
            summary_workers=2,
            hybrid_risk_triage=False,
            max_input_chars=1000,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.llm_client = _NoTriageClient()
    e.exploit_llm_client = e.llm_client
    e.masvs_mapping = {}
    e._load_summarize_prompt = lambda: "summarize"
    e._load_identify_risk_prompt = lambda: "risk"
    e._load_rule_signals = lambda _rules: (["keyword"], ["pattern"])
    e._collect_static_candidates = lambda *_args, **_kwargs: [str(keyword), str(pattern)]
    e._is_relevant_file = lambda *_args: True
    e._pattern_matched_files = lambda *_args: [str(pattern)]
    e.analyze_strings_xml = lambda *_args: []
    e.analyze_manifest = lambda *_args: []
    summary_context_order = []
    e.summarize_app = lambda _path, summaries: summary_context_order.extend(summaries) or "app"
    analyzed = []
    e.analyze_file = lambda path, _rules: analyzed.append(path) or []

    report_path = tmp_path / "triage-off-report.json"
    e.run("fixture.apk", output_file=str(report_path), no_decompile=True)
    report = json.loads(report_path.read_text())

    # Context remains in original candidate order; only deep scheduling priority changes.
    assert summary_context_order == [str(keyword), str(pattern)]
    assert analyzed == [str(pattern), str(keyword)]
    assert set(analyzed) == {str(keyword), str(pattern)}
    assert e.llm_client.calls == 2
    assert report["scan_metrics"]["summarization_calls"] == 2
    assert report["scan_metrics"]["risk_triage_calls"] == 0
    assert report["scan_metrics"]["risk_triage_seconds"] == 0.0
    assert report["scan_metrics"]["hybrid_risk_triage"] == "skipped_redundant"
    assert report["scan_metrics"]["deep_scan_targets"] == 2
    assert report["scan_metrics"]["deep_scan_priority"] == "static_pattern_then_scoped_stable"
    assert report["scan_metrics"]["deep_scan_files_scheduled"] == 2
    assert report["scan_metrics"]["deep_scan_files_completed"] == 2
    assert report["scan_metrics"]["deep_scan_files_error"] == 0
    assert report["scan_metrics"]["deep_scan_file_accounting_complete"] is True
    assert report["analysis_errors"] == []
    assert report["scan_status"] == "Completed"


def test_hybrid_failed_batch_fallback_is_unanalyzed_but_reaches_deep_scan(
    tmp_path, monkeypatch
):
    import json

    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    sources = decompiled / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    first = sources / "First.java"
    second = sources / "Second.java"
    first.write_text("first candidate source long enough for hybrid selection")
    second.write_text("second candidate source long enough for hybrid selection")
    (decompiled / "AndroidManifest.xml").write_text('<manifest package="com.example"/>')

    class _PartialThenEmptyClient:
        def analyze_code(self, code, context):
            if "BATCH OUTPUT CONTRACT" in context["vuln_prompt"]:
                items = json.loads(code)["items"]
                return json.dumps({items[0]["id"]: "summary-first"})
            return ""

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            filter_mode="hybrid",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
            scan_libraries=False,
            max_workers=1,
            summary_workers=1,
            summary_batch_size=2,
            hybrid_risk_triage=False,
            max_input_chars=1000,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.llm_client = _PartialThenEmptyClient()
    e.exploit_llm_client = e.llm_client
    e.masvs_mapping = {}
    e._load_summarize_prompt = lambda: "summarize"
    candidates = [str(first), str(second)]
    e._load_rule_signals = lambda _rules: (["candidate"], ["first"])
    e._collect_static_candidates = lambda *_args, **_kwargs: candidates
    e._is_relevant_file = lambda *_args: True
    e._pattern_matched_files = lambda *_args: [str(first)]
    e.analyze_strings_xml = lambda *_args: []
    e.analyze_manifest = lambda *_args: []
    e.summarize_app = lambda *_args: "fixture app"
    analyzed = []
    e.analyze_file = lambda path, _rules: analyzed.append(path) or []

    report_path = tmp_path / "batch-fallback-report.json"
    e.run("fixture.apk", output_file=str(report_path), no_decompile=True)
    report = json.loads(report_path.read_text())

    assert analyzed == candidates
    assert report["scan_metrics"]["summary_batch_requests"] == 1
    assert report["scan_metrics"]["summary_batch_valid_items"] == 1
    assert report["scan_metrics"]["summary_batch_fallback_items"] == 1
    assert report["scan_metrics"]["summarization_calls"] == 2
    assert report["scan_metrics"]["deep_scan_files_scheduled"] == 2
    assert report["scan_metrics"]["deep_scan_files_completed"] == 2
    assert report["analysis_errors"] == [{
        "file": str(second),
        "rule": "__summarization__",
        "stage": "summarization",
        "status": "Unanalyzed",
        "reason": "empty",
    }]
    assert report["scan_status"] == "CompletedWithErrors"


def test_hybrid_priority_executor_is_exhaustive_and_merges_in_priority_order(
    tmp_path, monkeypatch
):
    import json
    import time

    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    sources = decompiled / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    low_first = sources / "LowFirst.java"
    high_pattern = sources / "HighPattern.java"
    low_last = sources / "LowLast.java"
    for source in (low_first, high_pattern, low_last):
        source.write_text("candidate source content long enough for hybrid selection")
    (decompiled / "AndroidManifest.xml").write_text('<manifest package="com.example"/>')

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            filter_mode="hybrid",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
            scan_libraries=False,
            max_workers=2,
            summary_workers=2,
            hybrid_risk_triage=False,
            max_input_chars=1000,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    e.masvs_mapping = {}
    candidates = [str(low_first), str(high_pattern), str(low_last)]
    e._load_rule_signals = lambda _rules: (["candidate"], ["HighPattern"])
    e._collect_static_candidates = lambda *_args, **_kwargs: candidates
    e._is_relevant_file = lambda *_args: True
    e._pattern_matched_files = lambda *_args: [str(high_pattern)]
    e.summarize_chunks = lambda _root, file_list, **_kwargs: {
        path: f"summary:{path}" for path in file_list
    }
    e.analyze_strings_xml = lambda *_args: []
    e.analyze_manifest = lambda *_args: []
    e.summarize_app = lambda *_args: "fixture app"

    started = []

    def analyze(path, _rules):
        started.append(path)
        # Force completion order away from submission order. The final report must
        # still merge by stable priority, and the low-priority tail must still run.
        if path == str(high_pattern):
            time.sleep(0.03)
        if path == str(low_last):
            raise TimeoutError("low-priority fixture timeout")
        return [_finding(path, "sql_injection", "SQL Injection", status="Not Vulnerable")]

    e.analyze_file = analyze
    report_path = tmp_path / "priority-report.json"
    e.run("fixture.apk", output_file=str(report_path), no_decompile=True)
    report = json.loads(report_path.read_text())

    assert started[0] == str(high_pattern)
    assert set(started) == set(candidates)
    assert [result["file"] for result in report["results"]] == [
        str(high_pattern), str(low_first), str(low_last)
    ]
    metrics = report["scan_metrics"]
    assert metrics["deep_scan_targets"] == 3
    assert metrics["deep_scan_files_scheduled"] == 3
    assert metrics["deep_scan_files_completed"] == 2
    assert metrics["deep_scan_files_error"] == 1
    assert metrics["deep_scan_file_accounting_complete"] is True
    assert metrics["deep_rule_accounting_complete"] is True
    assert report["results"][-1]["status"] == "Error"
    assert report["analysis_errors"][-1]["status"] == "Unanalyzed"
    assert report["scan_status"] == "CompletedWithErrors"


def test_deep_scan_keyboard_interrupt_does_not_publish_clean_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    sources = decompiled / "sources" / "com" / "example"
    sources.mkdir(parents=True)
    candidate = sources / "Candidate.java"
    candidate.write_text("candidate source content long enough for hybrid selection")
    (decompiled / "AndroidManifest.xml").write_text('<manifest package="com.example"/>')

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            filter_mode="hybrid",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
            scan_libraries=False,
            max_workers=1,
            summary_workers=1,
            hybrid_risk_triage=False,
            max_input_chars=1000,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    e.masvs_mapping = {}
    e._load_rule_signals = lambda _rules: (["candidate"], ["candidate"])
    e._collect_static_candidates = lambda *_args, **_kwargs: [str(candidate)]
    e._is_relevant_file = lambda *_args: True
    e._pattern_matched_files = lambda *_args: [str(candidate)]
    e.summarize_chunks = lambda _root, file_list, **_kwargs: {
        path: "summary" for path in file_list
    }
    e.analyze_strings_xml = lambda *_args: []
    e.analyze_manifest = lambda *_args: []
    e.summarize_app = lambda *_args: "fixture app"
    e.analyze_file = lambda *_args: (_ for _ in ()).throw(KeyboardInterrupt())
    report_path = tmp_path / "must-not-exist.json"

    with pytest.raises(KeyboardInterrupt):
        e.run("fixture.apk", output_file=str(report_path), no_decompile=True)

    assert not report_path.exists()


def test_explicit_rule_selection_is_normalized_and_intersects_enabled_rules():
    e = _engine()
    e.settings = types.SimpleNamespace(
        rules=_SelectableRules(
            intent_redirection=True,
            sql_injection=True,
            webview_xss=False,
        )
    )

    assert e._resolve_active_rules(None) == ["intent_redirection", "sql_injection"]
    assert e._resolve_active_rules(" sql_injection ") == ["sql_injection"]
    assert e._resolve_active_rules(" sql_injection, intent_redirection,sql_injection ") == [
        "intent_redirection",
        "sql_injection",
    ]
    assert e._resolve_active_rules("webview_xss") == []


def test_explicit_selection_limits_candidate_signals_without_losing_selected_rule(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    sql_file = sources / "SQLActivity.java"
    intent_file = sources / "IntentRedirectionActivity.java"
    sql_file.write_text('db.execSQL("SELECT * FROM users WHERE id=" + attackerInput);')
    intent_file.write_text('Intent nested = getParcelableExtra("forward"); startActivity(nested);')

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(scan_libraries=False),
        rules=_SelectableRules(intent_redirection=True, sql_injection=True),
    )

    def candidates_for(selection):
        active = e._resolve_active_rules(selection)
        keywords, patterns = e._load_rule_signals(active)
        return set(e._collect_static_candidates(
            "hybrid", str(tmp_path), str(sources), keywords, patterns, True
        ))

    without_explicit = candidates_for(None)
    sql_only = candidates_for(" sql_injection ")
    multi = candidates_for("sql_injection, intent_redirection")

    assert without_explicit == {str(sql_file), str(intent_file)}
    assert sql_only == {str(sql_file)}
    assert multi == without_explicit


def test_empty_explicit_active_list_does_not_fall_back_to_all_rules(tmp_path):
    source = tmp_path / "SQLActivity.java"
    source.write_text('db.execSQL("DELETE FROM users");')
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(response='{"is_vulnerable": true}')
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    assert e.analyze_file(str(source), rules_to_run=[]) == []


def test_explicit_rule_selection_is_used_by_deep_scan(tmp_path):
    source = tmp_path / "CombinedActivity.java"
    source.write_text(
        'Intent nested = getParcelableExtra("forward"); startActivity(nested);\n'
        'db.execSQL("DELETE FROM users WHERE id=" + attackerInput);'
    )
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_SelectableRules(intent_redirection=True, sql_injection=True),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(
        response='{"is_vulnerable": true, "severity": "High", "description": "fixture"}'
    )
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    results = e.analyze_file(str(source), rules_to_run=["sql_injection"])

    assert [(result["rule"], result["status"]) for result in results] == [
        ("sql_injection", "Vulnerable")
    ]


def test_parameterized_query_signal_requires_agent_verdict(tmp_path):
    """Matching query() is candidate collection only; it must not create a finding."""
    source = tmp_path / "SafeDatabase.java"
    source.write_text(
        'db.query("users", columns, "name = ?", new String[]{userInput}, null, null, null);'
    )
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_SelectableRules(sql_injection=True),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(
        response='{"is_vulnerable": false, "description": "selectionArgs parameterizes input"}'
    )
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    results = e.analyze_file(str(source), rules_to_run=["sql_injection"])

    assert [(result["rule"], result["status"]) for result in results] == [
        ("sql_injection", "Not Vulnerable")
    ]


def test_canonicalized_file_constructor_signal_requires_agent_verdict(tmp_path):
    """new File() is a candidate signal; containment validation controls the verdict."""
    source = tmp_path / "SafeProvider.java"
    source.write_text(
        "File target = new File(base, attackerName);\n"
        "if (!target.getCanonicalPath().startsWith(base.getCanonicalPath())) throw new SecurityException();"
    )
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_SelectableRules(path_traversal=True),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(
        response='{"is_vulnerable": false, "description": "canonical containment is enforced"}'
    )
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    results = e.analyze_file(str(source), rules_to_run=["path_traversal"])

    assert [(result["rule"], result["status"]) for result in results] == [
        ("path_traversal", "Not Vulnerable")
    ]


@pytest.mark.parametrize(("rule_name", "filename", "source"), [
    (
        "intent_redirection",
        "BundleForwarder.java",
        'Intent nested = bundle.getParcelable("forward"); startActivity(nested);',
    ),
    (
        "pending_intent_hijacking",
        "PendingFactory.smali",
        "const/high16 v3, 0x2000000\n"
        "invoke-static {p0, v1, v2, v3}, Landroid/app/PendingIntent;->getActivity"
        "(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;",
    ),
])
def test_new_intent_and_pending_signals_reach_agent_analysis(tmp_path, rule_name, filename, source):
    target = tmp_path / filename
    target.write_text(source)
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            filter_mode="hybrid",
            max_input_chars=1000,
            use_cross_reference_context=False,
            scan_libraries=False,
            generate_exploit=False,
        ),
        rules=_SelectableRules(**{rule_name: True}),
    )
    e.call_graph_builder = None
    e.llm_client = _TriageClient(
        response='{"is_vulnerable": false, "description": "fixture reached agent"}'
    )
    e.masvs_mapping = {}
    e.analysis_errors = []
    e.vulnerability_findings = []

    results = e.analyze_file(str(target), rules_to_run=[rule_name])

    assert [(result["rule"], result["status"]) for result in results] == [
        (rule_name, "Not Vulnerable")
    ]


def test_standalone_strings_rule_result_is_not_tied_to_code_targets(tmp_path, monkeypatch):
    import json

    monkeypatch.chdir(tmp_path)
    decompiled = tmp_path / "output" / "fixture.apk_decompiled"
    decompiled.mkdir(parents=True)
    (decompiled / "AndroidManifest.xml").write_text("<manifest/>")

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="hybrid",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
        ),
        rules=_SelectableRules(hardcoded_secrets_xml=True, sql_injection=False),
    )
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    captured = {}
    finding = _finding("strings.xml", "hardcoded_secrets_xml", "Hardcoded Secrets (strings.xml)")

    def fake_strings(_output_dir, active_rules):
        captured["strings"] = active_rules
        return [finding]

    e.analyze_strings_xml = fake_strings
    e.analyze_manifest = lambda _path, active_rules: captured.setdefault("manifest", active_rules) and []
    e.summarize_app = lambda _path, _summaries: "fixture app"
    output = tmp_path / "report.json"

    e.run("fixture.apk", output_file=str(output), no_decompile=True, rules=" hardcoded_secrets_xml ")

    report = json.loads(output.read_text())
    assert captured["strings"] == ["hardcoded_secrets_xml"]
    assert captured["manifest"] == ["hardcoded_secrets_xml"]
    assert report["results"] == [finding]
    assert report["scan_status"] == "Completed"
    assert report["scan_metrics"]["candidates_raw"] == 0
    assert report["scan_metrics"]["candidates_scoped"] == 0
    assert report["scan_metrics"]["deep_scan_targets"] == 0
    assert report["scan_metrics"]["report_results"] == 1


def test_file_to_class_dotted():
    """[B] map a decompiled file path -> dotted class for manifest component lookup."""
    e = _engine()
    assert (e._file_to_class_dotted(
        "/o/App.apk_decompiled/sources/com/dlh/vulnerapp/IntentRedirectionActivity.java")
        == "com.dlh.vulnerapp.IntentRedirectionActivity")
    assert e._file_to_class_dotted("/o/dec/smali/com/a/b/C.smali") == "com.a.b.C"
    assert e._file_to_class_dotted("/o/dec/smali_classes3/com/a/D.smali") == "com.a.D"
    assert e._file_to_class_dotted("/o/nowhere/Foo.java") is None


def test_manifest_get_component_details_childless(tmp_path):
    """Regression: an <activity/> with NO child nodes is a *falsy* ElementTree Element, so
    get_component_details used to wrongly return {} for it (e.g. IntentRedirectionActivity,
    which has no intent-filter). It must be found via `is not None`."""
    from core.manifest_parser import ManifestParser
    m = tmp_path / "AndroidManifest.xml"
    m.write_text(
        '<?xml version="1.0"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">\n'
        '  <application>\n'
        '    <activity android:name="com.x.NoFilterActivity" android:exported="true"/>\n'
        '    <activity android:name="com.x.WithFilter" android:exported="true">\n'
        '      <intent-filter><action android:name="a"/></intent-filter>\n'
        '    </activity>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    p = ManifestParser(str(m))
    assert p.get_component_details("com.x.NoFilterActivity").get("exported") == "true"
    assert p.get_component_details("com.x.WithFilter").get("exported") == "true"
    assert p.get_component_details("com.x.DoesNotExist") == {}


# ---- PoC extension detection: shebang/first-line wins over content sniffing ---
def test_poc_extension_bash_with_embedded_python_heredoc():
    """Regression: a real generated PoC was `#!/bin/bash` that embeds a
    `python3 - << 'EOF' ... EOF` heredoc (to do background logcat monitoring, which
    Bash can't easily do alone). The old whole-content scan matched "import "/"def "
    INSIDE the heredoc and saved this valid, directly-executable Bash script as
    ".py". The shebang must win: it's what the OS actually uses to run the file."""
    e = _engine()
    bash_with_heredoc = (
        "#!/bin/bash\n"
        "echo starting\n"
        "python3 - << 'PYEOF'\n"
        "import subprocess\n"
        "import threading\n"
        "def monitor_logcat():\n"
        "    pass\n"
        "PYEOF\n"
    )
    assert e._detect_poc_extension(bash_with_heredoc) == ".sh"


def test_poc_extension_bash_with_embedded_frida_js():
    """Same principle, different embedded language: shebang still wins."""
    e = _engine()
    bash_with_js = "#!/bin/bash\necho hi\n" + "Java.perform(function() { console.log(1); });"
    assert e._detect_poc_extension(bash_with_js) == ".sh"


def test_poc_extension_pure_python():
    e = _engine()
    assert e._detect_poc_extension("#!/usr/bin/env python3\nimport os\ndef f(): pass") == ".py"


def test_poc_extension_pure_frida_js():
    e = _engine()
    assert e._detect_poc_extension("Java.perform(function(){ console.log(1); });") == ".js"


def test_poc_extension_pure_html():
    e = _engine()
    assert e._detect_poc_extension("<!DOCTYPE html>\n<html><body></body></html>") == ".html"


def test_poc_extension_falls_back_to_content_sniffing_without_shebang():
    """No shebang / first-line signal at all -> content-sniffing fallback still works."""
    e = _engine()
    assert e._detect_poc_extension("some notes\nadb shell am start -n a/b\n") == ".sh"
    assert e._detect_poc_extension("some notes\nimport os\nrest of script\n") == ".py"


def test_poc_extension_unknown_content_is_txt():
    e = _engine()
    assert e._detect_poc_extension("just some random output with no signals") == ".txt"


# ---- exploit-generation provider routing (llm.exploit_provider/exploit_model) --
def _llm_settings(**overrides):
    base = dict(
        provider="ollama", model="deepseek-coder-v2:latest", ollama_url="http://localhost:11434",
        gemini_model="gemini-2.0-flash", gemini_api_key="g",
        groq_model="llama-3.1-8b-instant", groq_api_key="g",
        openai_model="gpt-4-turbo", openai_api_key="o",
        anthropic_model="claude-opus-4-6", anthropic_api_key="a",
        openrouter_model="moonshotai/kimi-k3", openrouter_api_key="or",
        router9_model="gc/gemini-2.5-pro", router9_api_key="r9", router9_base_url="http://localhost:20128/v1/chat/completions",
        codex_model=None, codex_cli_path="codex", codex_timeout=600,
        codex_sandbox="read-only", codex_reasoning_effort=None,
        max_tokens=4096, exploit_provider=None, exploit_model=None,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


def _engine_with_settings(generate_exploit, use_cache=False, **llm_overrides):
    e = _engine()
    e.settings = types.SimpleNamespace(
        llm=_llm_settings(**llm_overrides),
        analysis=types.SimpleNamespace(use_cache=use_cache, generate_exploit=generate_exploit),
    )
    return e


def test_build_llm_client_model_override():
    e = _engine()
    e.settings = types.SimpleNamespace(llm=_llm_settings(), analysis=types.SimpleNamespace(use_cache=False))
    client = e._build_llm_client("anthropic", model_override="custom-model")
    assert client.model == "custom-model"  # override wins over anthropic_model default
    default_client = e._build_llm_client("anthropic")
    assert default_client.model == "claude-opus-4-6"  # no override -> that provider's own default


def test_exploit_client_defaults_to_main_when_unset():
    """No exploit_provider/exploit_model set -> exploit generation reuses the main client
    (no second object built at all)."""
    e = _engine_with_settings(generate_exploit=True)
    e._setup_llm_client()
    assert e.exploit_llm_client is e.llm_client


def test_exploit_client_skipped_when_generate_exploit_is_off():
    """A typo'd/unused exploit_provider must NEVER affect a normal scan: the separate
    client is only built when exploit generation is actually requested."""
    e = _engine_with_settings(generate_exploit=False, exploit_provider="anthropic")
    e._setup_llm_client()
    assert e.exploit_llm_client is e.llm_client


def test_exploit_client_routes_to_separate_provider():
    e = _engine_with_settings(generate_exploit=True, exploit_provider="anthropic")
    e._setup_llm_client()
    assert e.exploit_llm_client is not e.llm_client
    assert e.exploit_llm_client.model == "claude-opus-4-6"
    assert e.llm_client.model == "deepseek-coder-v2:latest"  # main (ollama) client untouched


def test_exploit_client_model_override_without_changing_provider():
    """exploit_model alone (same provider as main) must still build a separate client."""
    e = _engine_with_settings(generate_exploit=True, provider="anthropic", exploit_model="claude-sonnet-4-5")
    e._setup_llm_client()
    assert e.exploit_llm_client is not e.llm_client
    assert e.exploit_llm_client.model == "claude-sonnet-4-5"
    assert e.llm_client.model == "claude-opus-4-6"


def test_exploit_client_falls_back_on_bad_provider():
    """A misconfigured exploit_provider must not crash the scan -> falls back to main."""
    e = _engine_with_settings(generate_exploit=True, exploit_provider="not_a_real_provider")
    e._setup_llm_client()  # must not raise
    assert e.exploit_llm_client is e.llm_client


# ---- attack surface map: structured inventory, not narrative text -------------
class _StubLLM:
    def __init__(self, response):
        self.response = response

    def analyze_code(self, code, ctx):
        return self.response


class _CapturingLLM(_StubLLM):
    def __init__(self, response):
        super().__init__(response)
        self.contexts = []

    def analyze_code(self, code, ctx):
        self.contexts.append(ctx)
        return super().analyze_code(code, ctx)


class _RaisingLLM:
    def __init__(self, error):
        self.error = error

    def analyze_code(self, _code, _ctx):
        raise self.error


def test_app_summary_exception_is_recorded_as_unanalyzed(tmp_path):
    e = _engine()
    e.llm_client = _RaisingLLM(TimeoutError("fixture timeout"))
    e.analysis_errors = []
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")

    assert e.summarize_app(str(manifest), {}) == ""
    assert e.analysis_errors[0]["stage"] == "app_summary"
    assert e.analysis_errors[0]["status"] == "Unanalyzed"
    assert e.analysis_errors[0]["reason"] == "timeout"


def test_attack_surface_map_returns_parsed_dict_on_success(tmp_path):
    """v1.3.0: was a raw narrative string; now a small structured inventory dict."""
    e = _engine()
    e.llm_client = _StubLLM(
        '{"exported_activities": ["WebViewActivity"], "deep_links": '
        '[{"scheme": "dlh", "host": "webview", "handler": "WebViewActivity"}], '
        '"network": ["webview"], "file_io": false, "ipc": true, '
        '"deserialization": false, "reflection": false, "manifest_flags": {"debuggable": true}}'
    )
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    result = e.generate_attack_surface_map(str(manifest), {})
    assert isinstance(result, dict)
    assert result["exported_activities"] == ["WebViewActivity"]
    assert result["deep_links"][0]["handler"] == "WebViewActivity"
    assert result["ipc"] is True
    assert "error" not in result


def test_attack_surface_map_reports_error_on_empty_response(tmp_path):
    e = _engine()
    e.llm_client = _StubLLM("")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    result = e.generate_attack_surface_map(str(manifest), {})
    assert "error" in result  # transparent failure, not a silent empty/null map
    assert e.analysis_errors[0]["stage"] == "attack_surface"
    assert e.analysis_errors[0]["reason"] == "empty"


def test_attack_surface_map_reports_error_on_unparseable_response(tmp_path):
    e = _engine()
    e.llm_client = _StubLLM("Sure, here is the attack surface: WebViewActivity is exported...")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest/>")
    result = e.generate_attack_surface_map(str(manifest), {})
    assert "error" in result
    assert "is_vulnerable" not in result  # must NOT leak the vuln-verdict fallback shape
    assert e.analysis_errors[0]["stage"] == "attack_surface"
    assert e.analysis_errors[0]["reason"] == "unparseable"
    assert e.analysis_errors[0]["raw_response"].startswith("Sure, here")


def test_exploit_generation_exception_is_recorded_without_removing_finding(tmp_path):
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(use_cross_reference_context=False)
    )
    e.exploit_llm_client = _RaisingLLM(RuntimeError("fixture exploit failure"))
    e.analysis_errors = []
    e.vulnerability_findings = [{"rule_name": "sql_injection"}]

    poc_result = e._generate_poc(
        str(tmp_path / "SQLActivity.java"),
        "db.execSQL(userInput);",
        "tainted SQL reaches execSQL",
        "sql_injection",
    )

    assert e.vulnerability_findings == [{"rule_name": "sql_injection"}]
    assert e.analysis_errors[0]["stage"] == "exploit_generation"
    assert e.analysis_errors[0]["status"] == "Unanalyzed"
    assert e.analysis_errors[0]["reason"] == "exception"
    assert poc_result["status"] == "Unanalyzed"
    assert poc_result["error"]["stage"] == "generation"


def test_generated_poc_has_separate_status_and_does_not_mutate_finding(tmp_path):
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(use_cross_reference_context=False)
    )
    e.exploit_llm_client = _StubLLM("#!/bin/bash\necho verification")
    e.analysis_errors = []
    e.scan_metrics = {"exploit_successes": 0}
    e.final_exploit_dir = str(tmp_path / "exploits")
    finding = {"rule_name": "sql_injection"}
    e.vulnerability_findings = [finding.copy()]

    poc_result = e._generate_poc(
        str(tmp_path / "SQLActivity.java"),
        "db.execSQL(userInput);",
        "tainted SQL reaches execSQL",
        "sql_injection",
    )

    assert e.vulnerability_findings == [finding]
    assert poc_result["status"] == "generated"
    assert poc_result["rule"] == "sql_injection"
    assert __import__("pathlib").Path(poc_result["artifact_path"]).read_text().startswith("#!/bin/bash")
    assert e.scan_metrics["exploit_generated"] == 1
    assert e.scan_metrics["exploit_successes"] == 1


def test_chained_exploit_records_every_poc_status_without_removing_findings(monkeypatch):
    e = _engine()
    e.scan_metrics = {"exploit_attempts": 0}
    e.poc_results = []
    e.vulnerability_findings = [
        {"file_path": "A.java", "code_snippet": "a", "vuln_description": "one", "rule_name": "rule_a"},
        {"file_path": "B.java", "code_snippet": "b", "vuln_description": "two", "rule_name": "rule_b"},
    ]
    original_findings = [finding.copy() for finding in e.vulnerability_findings]

    def fake_generate(file_path, _code, _description, rule_name, _context):
        status = "generated" if rule_name == "rule_a" else "Unanalyzed"
        return e._poc_result(file_path, rule_name, status)

    monkeypatch.setattr(e, "_generate_poc", fake_generate)
    e._generate_chained_exploits()

    assert e.vulnerability_findings == original_findings
    assert [result["status"] for result in e.poc_results] == ["generated", "Unanalyzed"]
    assert e.scan_metrics["exploit_attempts"] == 2


def test_poc_validator_rejects_parcelable_sent_as_string_and_crash_as_success():
    e = _engine()
    artifact = (
        "#!/bin/bash\n"
        "adb shell am start -n com.example/.RedirectActivity "
        "--es forward_intent payload\n"
        "echo 'PASS: ClassCastException type-confusion crash observed'\n"
    )
    source = (
        "package com.example; class RedirectActivity { void go() { "
        "Intent next = getIntent().getParcelableExtra(\"forward_intent\"); "
        "startActivity(next); } }"
    )

    validation = e._validate_poc_artifact(
        artifact, ".sh", "intent_redirection", "RedirectActivity.java", source,
        "Component: com.example.RedirectActivity exported=true",
    )

    assert validation["status"] == "invalid"
    failed = [check["detail"] for check in validation["checks"] if check["status"] == "failed"]
    assert any("PoC sends string, target reads parcelable" in detail for detail in failed)
    assert "crash is not proof of Intent Redirection" in failed


def _frida_intent_redirection_artifact(*, marker_receiver="nested", extra_outer=False,
                                        observe_marker=True):
    outer_extra = "  outer.putExtra('invented_outer_key', 'value');\n" if extra_outer else ""
    marker_read = (
        "  var observed = nested.getStringExtra('verification_marker');\n"
        if observe_marker else ""
    )
    return (
        "Java.perform(function () {\n"
        "  var Intent = Java.use('android.content.Intent');\n"
        "  var Parcelable = Java.use('android.os.Parcelable');\n"
        "  var ActivityThread = Java.use('android.app.ActivityThread');\n"
        "  var context = ActivityThread.currentApplication().getApplicationContext();\n"
        "  var nested = Intent.$new();\n"
        "  var decoy = Intent.$new();\n"
        f"  {marker_receiver}.putExtra('verification_marker', 'observed');\n"
        + marker_read
        + "  var outer = Intent.$new();\n"
        + outer_extra
        + "  outer.putExtra.overload('java.lang.String', 'android.os.Parcelable')\n"
        "    .call(outer, 'forward_intent', Java.cast(nested, Parcelable));\n"
        "  context.startActivity(outer);\n"
        "  console.log('manual runtime verification required');\n"
        "});\n"
    )


def _intent_redirection_source():
    return (
        "package com.example; class RedirectActivity { void go() { "
        "Intent next = getIntent().getParcelableExtra(\"forward_intent\"); "
        "startActivity(next); } }"
    )


def test_poc_validator_accepts_observation_extra_on_proven_nested_intent():
    validation = _engine()._validate_poc_artifact(
        _frida_intent_redirection_artifact(), ".js", "intent_redirection",
        "RedirectActivity.java", _intent_redirection_source(),
        "Component: com.example.RedirectActivity\nExported: true\n",
    )

    assert validation["status"] == "valid"
    assert any(
        check["name"] == "extra_provenance"
        and check["status"] == "warning"
        and "verification_marker" in check["detail"]
        and "nested Intent observation marker" in check["detail"]
        for check in validation["checks"]
    )


def test_poc_validator_still_rejects_invented_outer_intent_extra():
    validation = _engine()._validate_poc_artifact(
        _frida_intent_redirection_artifact(extra_outer=True), ".js",
        "intent_redirection", "RedirectActivity.java",
        _intent_redirection_source(),
        "Component: com.example.RedirectActivity\nExported: true\n",
    )

    assert validation["status"] == "invalid"
    assert any(
        check["name"] == "extra_provenance"
        and check["status"] == "failed"
        and "invented_outer_key" in check["detail"]
        for check in validation["checks"]
    )


def test_poc_validator_does_not_trust_marker_on_unforwarded_intent_object():
    validation = _engine()._validate_poc_artifact(
        _frida_intent_redirection_artifact(marker_receiver="decoy"), ".js",
        "intent_redirection", "RedirectActivity.java",
        _intent_redirection_source(),
        "Component: com.example.RedirectActivity\nExported: true\n",
    )

    assert validation["status"] == "invalid"
    assert any(
        check["name"] == "extra_provenance"
        and check["status"] == "failed"
        and "verification_marker" in check["detail"]
        for check in validation["checks"]
    )


def test_poc_validator_rejects_unobserved_unknown_nested_payload_extra():
    validation = _engine()._validate_poc_artifact(
        _frida_intent_redirection_artifact(observe_marker=False), ".js",
        "intent_redirection", "RedirectActivity.java",
        _intent_redirection_source(),
        "Component: com.example.RedirectActivity\nExported: true\n",
    )

    assert validation["status"] == "invalid"
    assert any(
        check["name"] == "extra_provenance"
        and check["status"] == "failed"
        and "verification_marker" in check["detail"]
        for check in validation["checks"]
    )


def test_poc_validator_rejects_invented_literal_ipc_identifiers():
    e = _engine()
    artifact = (
        "#!/bin/bash\n"
        "adb shell am start -n com.fake/.InventedActivity "
        "-a com.fake.INVENTED --es invented_key value\n"
    )
    validation = e._validate_poc_artifact(
        artifact, ".sh", "intent_spoofing", "RealActivity.java",
        "class RealActivity {}", "Component: com.real.RealActivity",
    )

    assert validation["status"] == "invalid"
    failed_names = {check["name"] for check in validation["checks"] if check["status"] == "failed"}
    assert {"component_provenance", "action_provenance", "extra_provenance"} <= failed_names


def test_poc_validator_accepts_preference_activity_framework_extras_conditionally():
    e = _engine()
    artifact = (
        "#!/bin/bash\n"
        "COMPONENT='com.example/.FragmentActivity'\n"
        "adb shell am start -W -n \"$COMPONENT\" "
        "--es ':android:show_fragment' android.preference.PreferenceFragment "
        "--ez ':android:no_headers' true\n"
        "echo 'PASS: attacker-selected fragment was instantiated'\n"
    )
    source = (
        "package com.example; public final class FragmentActivity extends PreferenceActivity { "
        "protected boolean isValidFragment(String fragmentName) { return true; } }"
    )

    validation = e._validate_poc_artifact(
        artifact, ".sh", "universal_logic_flaw", "FragmentActivity.java", source,
        "Component: com.example.FragmentActivity\nPackage: com.example\nExported: true\n",
    )

    assert validation["status"] == "valid"
    passed = [check["detail"] for check in validation["checks"] if check["status"] == "passed"]
    assert ":android:show_fragment: PreferenceActivity framework contract" in passed
    assert ":android:no_headers: PreferenceActivity framework contract" in passed
    assert "isValidFragment unconditionally returns true" in passed
    assert "manifest marks PreferenceActivity component exported" in passed


def test_preference_activity_framework_extras_are_not_globally_allowlisted():
    e = _engine()
    artifact = (
        "#!/bin/bash\n"
        "adb shell am start -n com.example/.OrdinaryActivity "
        "--es ':android:show_fragment' android.preference.PreferenceFragment\n"
    )

    validation = e._validate_poc_artifact(
        artifact, ".sh", "universal_logic_flaw", "OrdinaryActivity.java",
        "package com.example; class OrdinaryActivity extends Activity {}",
        "Component: com.example.OrdinaryActivity\nExported: true\n",
    )

    assert validation["status"] == "invalid"
    assert any(
        check["name"] == "extra_provenance" and check["status"] == "failed"
        for check in validation["checks"]
    )


def test_preference_activity_framework_extra_type_is_still_enforced():
    e = _engine()
    artifact = (
        "#!/bin/bash\n"
        "adb shell am start -n com.example/.FragmentActivity "
        "--ei ':android:show_fragment' 1\n"
    )
    source = "class FragmentActivity extends android.preference.PreferenceActivity {}"

    validation = e._validate_poc_artifact(
        artifact, ".sh", "universal_logic_flaw", "FragmentActivity.java", source,
        "Component: com.example.FragmentActivity\nExported: true\n",
    )

    assert validation["status"] == "invalid"
    assert any(
        check["name"] == "extra_type" and check["status"] == "failed"
        and "PoC sends int, target reads string" in check["detail"]
        for check in validation["checks"]
    )


def test_preference_activity_framework_contract_supports_smali():
    e = _engine()
    smali = (
        ".class public Lcom/example/FragmentActivity;\n"
        ".super Landroid/preference/PreferenceActivity;\n"
        ".method protected isValidFragment(Ljava/lang/String;)Z\n"
        "    .locals 1\n"
        "    const/4 v0, 0x1\n"
        "    return v0\n"
        ".end method\n"
    )

    assert e._framework_extra_types(smali)[":android:show_fragment"] == "string"
    assert e._preference_activity_allows_fragment(smali) is True


def test_invalid_poc_artifact_is_preserved_and_finding_is_not_removed(tmp_path):
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(use_cross_reference_context=False)
    )
    e.exploit_llm_client = _StubLLM("#!/bin/bash\nif ; then\n  echo broken\nfi")
    e.analysis_errors = []
    e.scan_metrics = {"exploit_successes": 0, "exploit_validation_errors": 0}
    e.final_exploit_dir = str(tmp_path / "exploits")
    finding = {"rule_name": "sql_injection"}
    e.vulnerability_findings = [finding.copy()]

    poc_result = e._generate_poc(
        str(tmp_path / "SQLActivity.java"), "db.execSQL(userInput);",
        "tainted SQL reaches execSQL", "sql_injection",
    )

    assert e.vulnerability_findings == [finding]
    assert poc_result["status"] == "validation-error"
    assert __import__("pathlib").Path(poc_result["artifact_path"]).exists()
    assert poc_result["validation"]["status"] == "invalid"
    assert e.scan_metrics["exploit_generated"] == 1
    assert e.scan_metrics["exploit_successes"] == 0
    assert e.scan_metrics["exploit_validation_errors"] == 1
    assert e.analysis_errors[0]["stage"] == "exploit_validation"
    assert e.analysis_errors[0]["status"] == "Unanalyzed"


def test_hardcoded_secret_rule_key_without_payload_is_unanalyzed_not_clean(tmp_path):
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(use_cross_reference_context=False)
    )
    client = _CapturingLLM("#!/bin/bash\necho should-not-run")
    e.exploit_llm_client = client
    e.analysis_errors = []
    e.scan_metrics = {"exploit_errors": 0}
    finding = {"rule_name": "hardcoded_secrets"}
    e.vulnerability_findings = [finding.copy()]

    poc_result = e._generate_poc(
        str(tmp_path / "Secrets.java"), "class Secrets {}",
        "model reported a hardcoded secret", "hardcoded_secrets",
    )

    assert client.contexts == []
    assert poc_result["status"] == "Unanalyzed"
    assert poc_result["error"]["reason"] == "missing_secret_evidence"
    assert e.vulnerability_findings == [finding]
    assert e.analysis_errors[0]["status"] == "Unanalyzed"


def test_intent_redirection_prompt_requires_real_parcelable_and_no_crash_claim(tmp_path):
    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(use_cross_reference_context=False)
    )
    frida = (
        "Java.perform(function () {\n"
        "  var Intent = Java.use('android.content.Intent');\n"
        "  var ActivityThread = Java.use('android.app.ActivityThread');\n"
        "  var context = ActivityThread.currentApplication().getApplicationContext();\n"
        "  var outer = Intent.$new();\n"
        "  outer.setClassName('com.example', 'com.example.IntentRedirectionActivity');\n"
        "  var nested = Intent.$new();\n"
        "  nested.setClassName('com.example', 'com.example.SQLActivity');\n"
        "  outer.putExtra.overload('java.lang.String', 'android.os.Parcelable')"
        ".call(outer, 'forward_intent', nested);\n"
        "  outer.addFlags(0x10000000);\n"
        "  context.startActivity(outer);\n"
        "  console.log('manual runtime verification required');\n"
        "});\n"
    )
    client = _CapturingLLM(frida)
    e.exploit_llm_client = client
    e.analysis_errors = []
    e.scan_metrics = {"exploit_successes": 0, "exploit_validation_errors": 0}
    e.final_exploit_dir = str(tmp_path / "exploits")

    poc_result = e._generate_poc(
        str(tmp_path / "IntentRedirectionActivity.java"),
        'package com.example; class IntentRedirectionActivity { '
        'Intent next = getIntent().getParcelableExtra("forward_intent"); startActivity(next); } '
        'class SQLActivity {}',
        "nested Intent is forwarded without validation", "intent_redirection",
    )

    prompt = client.contexts[0]["system_prompt"]
    assert "Rule key: `intent_redirection`" in prompt
    assert "NEVER send that value with ADB `--es`" in prompt
    assert "crash is a failed verification" in prompt
    assert poc_result["status"] == "generated"
    assert poc_result["runtime_status"] == "not-run"


def test_fatal_pipeline_error_writes_non_clean_partial_report(tmp_path):
    import json

    e = _engine()
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    e.analysis_errors = []
    e.final_output_file = str(tmp_path / "failed.json")
    e.apk_name = "broken.apk"
    e._record_pipeline_error("broken.apk", "apktool_decompilation", "exception", "bad apk")

    e._write_failed_scan_report()

    report = json.loads((tmp_path / "failed.json").read_text())
    assert report["scan_status"] == "Error"
    assert report["results"] == []
    assert report["analysis_errors"][0]["stage"] == "apktool_decompilation"
    assert report["analysis_errors"][0]["status"] == "Unanalyzed"


# ---- 9Router client: response body parsing ---------------------------------------
def _router9(**kw):
    kw.setdefault("model", "gc/gemini-2.5-pro")
    kw.setdefault("api_key", "k")
    kw.setdefault("base_url", "http://x/v1/chat/completions")
    return Router9Client(**kw)


def test_router9_parses_real_world_sse_stream():
    """Regression fixture: the exact SSE shape observed from a real 9Router instance
    (chat.completion.chunk objects, role-only first delta, content delta, then a
    finish_reason chunk with usage) — no `stream:true` was even requested."""
    r9 = _router9()
    body = "\n".join([
        '',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}',
        '',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{"content":"Hello "},"finish_reason":null}]}',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{"content":"9Router!"},"finish_reason":null}]}',
        'data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gemini-2.5-pro","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}',
        'data: [DONE]',
    ])
    assert r9._extract_content(body) == "Hello 9Router!"


def test_router9_sse_stream_stops_at_done_and_skips_malformed():
    r9 = _router9()
    body = "\n".join([
        'data: {"choices":[{"delta":{"content":"A"}}]}',
        'data: not-json-garbage',
        'data: {"choices":[{"delta":{"content":"B"}}]}',
        'data: [DONE]',
        'data: {"choices":[{"delta":{"content":"C-should-not-appear"}}]}',
    ])
    assert r9._extract_content(body) == "AB"


def test_router9_sse_stream_empty_on_no_data_lines():
    r9 = _router9()
    assert r9._extract_content("\n".join(["", "not an sse line"])) == ""


def test_router9_extracts_plain_json_mislabeled_as_event_stream():
    """Regression: 9Router has been observed sending `Content-Type: text/event-stream`
    while the actual body is a single complete `chat.completion` JSON object glued
    directly to a trailing `data: [DONE]` with NO separating newline. Since that blob
    never starts with `data:`, the old line-based SSE parser silently dropped it and
    every single 9Router call returned empty content — this is the exact shape that
    triggered '9Router API returned empty response' during real scans."""
    r9 = _router9()
    body = (
        '{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"cbcn-glm-5.2",'
        '"choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},'
        '"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}'
        'data: [DONE]\n\n'
    )
    assert r9._extract_content(body) == "Hello!"


def test_router9_extracts_plain_json_without_trailing_garbage():
    r9 = _router9()
    body = '{"choices":[{"message":{"content":"plain response"}}]}'
    assert r9._extract_content(body) == "plain response"


def test_router9_construct_prompt_survives_braces_in_code():
    """Java/Kotlin code is full of '{' '}' and must survive substitution as a VALUE."""
    r9 = _router9()
    prompt = r9._construct_prompt(
        "if (a) { b(); }",
        {"system_prompt": "SYS", "vuln_prompt": "Analyze {code_snippet} at {file_path}", "file_path": "F.java"},
    )
    assert "if (a) { b(); }" in prompt and "F.java" in prompt and prompt.startswith("SYS")


# ---- PoC validation must follow string constants, not only literals -------------
def test_put_extra_key_resolved_through_constant():
    """Regression: PoCs hoist keys into constants (var EXTRA_KEY = "forward_intent").
    A literal-only regex made those calls invisible and reported "nested Parcelable
    extra is never sent" against a script that sends it correctly."""
    poc = """
    var EXTRA_KEY = "forward_intent";
    var inner = Intent.$new();
    var outer = Intent.$new();
    outer.putExtra.overload("java.lang.String", "android.os.Parcelable").call(outer, EXTRA_KEY, inner);
    """
    keys = [c["key"] for c in _engine()._frida_put_extra_calls(poc)]
    assert "forward_intent" in keys


def test_literal_put_extra_key_still_works():
    poc = 'outer.putExtra("direct_key", "v");'
    assert [c["key"] for c in _engine()._frida_put_extra_calls(poc)] == ["direct_key"]


def test_observation_marker_via_constant_and_has_extra_is_accepted():
    """The marker a PoC writes to the nested Intent and reads back is local to the
    verification flow, not part of the victim's input contract. It is probed with
    hasExtra() as often as get*Extra(), and through a constant — all three were missed,
    failing a valid 5KB Frida script."""
    poc = """
    var MARKER_KEY = "ir_verify_marker";
    var EXTRA_KEY = "forward_intent";
    var Intent = Java.use("android.content.Intent");
    var inner = Intent.$new();
    var outer = Intent.$new();
    if (intent.hasExtra(MARKER_KEY)) { var m = intent.getStringExtra(MARKER_KEY); }
    inner.putExtra(MARKER_KEY, "value");
    outer.putExtra.overload("java.lang.String", "android.os.Parcelable").call(outer, EXTRA_KEY, inner);
    startActivity(outer);
    """
    code = 'Intent forward = getIntent().getParcelableExtra("forward_intent"); startActivity(forward);'
    manifest = '<activity android:exported="true" android:name="com.dlh.vulnerapp.IntentRedirectionActivity"/>'
    result = _engine()._validate_poc_artifact(
        poc, ".js", "intent_redirection", "IntentRedirectionActivity.java", code, manifest, "")
    extra = [c for c in result["checks"] if c["name"] == "extra_provenance"]
    assert extra and all(c["status"] != "failed" for c in extra)


def test_unknown_extra_on_outer_intent_still_fails():
    """The guard still applies where it matters: an extra invented on the OUTER Intent
    is not part of the component's input contract and must be flagged."""
    poc = """
    var Intent = Java.use("android.content.Intent");
    var outer = Intent.$new();
    outer.putExtra("totally_invented_key", "v");
    startActivity(outer);
    """
    code = 'Intent forward = getIntent().getParcelableExtra("forward_intent");'
    manifest = '<activity android:exported="true" android:name="com.dlh.vulnerapp.IntentRedirectionActivity"/>'
    result = _engine()._validate_poc_artifact(
        poc, ".js", "intent_redirection", "IntentRedirectionActivity.java", code, manifest, "")
    extra = [c for c in result["checks"] if c["name"] == "extra_provenance"]
    assert any(c["status"] == "failed" for c in extra)


# ---- PoC generation runs in parallel without changing results -------------------
def test_poc_generation_preserves_order_and_covers_every_finding():
    """PoC calls are the most expensive in the pipeline and findings are independent, so
    they run on the shared worker pool. Order and coverage must be unchanged: the report
    pairs poc_results with findings positionally."""
    import types

    e = _engine()
    e.scan_metrics = {}
    e._metrics_lock = __import__("threading").Lock()
    e.poc_results = []
    e.settings = types.SimpleNamespace(analysis=types.SimpleNamespace(max_workers=4))
    e.vulnerability_findings = [
        {"file_path": f"F{i}.java", "code_snippet": "c", "vuln_description": "d",
         "rule_name": f"rule_{i}"} for i in range(6)
    ]
    e._build_global_context = lambda: "ctx"
    e._generate_poc = lambda fp, _c, _d, rule, _ctx: e._poc_result(fp, rule, "generated")

    e._generate_chained_exploits()
    assert [r["rule"] for r in e.poc_results] == [f"rule_{i}" for i in range(6)]
    assert e.scan_metrics["exploit_attempts"] == 6


def test_poc_generation_is_serial_without_settings():
    """An Engine built without settings (tests, partial pipelines) must degrade to
    serial rather than crash on a missing max_workers."""
    e = _engine()
    e.scan_metrics = {}
    e.poc_results = []
    e.vulnerability_findings = [
        {"file_path": "A.java", "code_snippet": "a", "vuln_description": "d", "rule_name": "r"},
    ]
    e._build_global_context = lambda: "ctx"
    e._generate_poc = lambda fp, _c, _d, rule, _ctx: e._poc_result(fp, rule, "generated")
    e._generate_chained_exploits()
    assert len(e.poc_results) == 1


# ---- truncated provider responses must not pass as complete ---------------------
def test_truncated_response_is_rejected_not_reported_as_success(monkeypatch):
    """Regression: a reasoning model spent 8190 of 8192 tokens on hidden reasoning and
    returned a single character with finish_reason="length". The client logged SUCCESS
    and the engine saved that stub as a PoC script. Truncation must fail loudly instead,
    naming the fix, since retrying on the same budget truncates identically."""
    truncated = (
        '{"choices":[{"finish_reason":"length","index":0,'
        '"message":{"content":"`","role":"assistant"}}],"object":"chat.completion"}'
    )

    class _Resp:
        status_code = 200
        text = truncated

        def raise_for_status(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import modules.llm_client.router9 as mod
    monkeypatch.setattr(mod.requests, "post", lambda *a, **k: _Resp())
    assert _router9(max_tokens=8192).analyze_code("code", {"system_prompt": "", "vuln_prompt": "v"}) == ""


def test_finish_reason_is_read_from_both_wire_formats():
    """9Router answers as plain JSON or SSE depending on the call, so the stop reason
    has to be read from both."""
    plain = ('{"choices":[{"finish_reason":"length","message":{"content":"x"}}]}')
    assert _router9()._extract_content_and_reason(plain) == ("x", "length")

    sse = "\n".join([
        'data: {"choices":[{"delta":{"content":"par"},"finish_reason":null}]}',
        'data: {"choices":[{"delta":{"content":"tial"},"finish_reason":"length"}]}',
        "data: [DONE]",
    ])
    assert _router9()._extract_content_and_reason(sse) == ("partial", "length")


def test_complete_response_still_succeeds():
    """A normal stop must stay untouched — the guard only fires on truncation."""
    body = '{"choices":[{"finish_reason":"stop","message":{"content":"all good"}}]}'
    assert _router9()._extract_content_and_reason(body) == ("all good", "stop")
    assert _router9()._extract_content(body) == "all good"


# ---- PoC validation: nested payload action is attacker-chosen -------------------
def _validate_intent_redirection_poc(poc: str):
    code = 'Intent forward = getIntent().getParcelableExtra("forward_intent"); startActivity(forward);'
    manifest = '<activity android:exported="true" android:name="com.dlh.vulnerapp.IntentRedirectionActivity"/>'
    return _engine()._validate_poc_artifact(
        poc, ".js", "intent_redirection", "IntentRedirectionActivity.java",
        code, manifest, "",
    )


def test_nested_payload_action_is_not_required_in_manifest():
    """Regression: Intent Redirection means the victim forwards an Intent it never
    declared, so the NESTED action is attacker-chosen by definition. Requiring it to
    appear in the manifest inverts the threat model — it rejected a correct PoC whose
    nested payload used android.intent.action.VIEW."""
    poc = """
    Java.perform(function () {
        var Intent = Java.use("android.content.Intent");
        var Parcelable = Java.use("android.os.Parcelable");
        var redirect = Intent.$new();
        var nested = Intent.$new();
        nested.setAction("android.intent.action.VIEW");
        redirect.putExtra("forward_intent", Java.cast(nested, Parcelable));
        startActivity(redirect);
    });
    """
    checks = _validate_intent_redirection_poc(poc)["checks"]
    action = [c for c in checks if c["name"] == "action_provenance"]
    assert action and all(c["status"] != "failed" for c in action)
    assert any("attacker-controlled nested payload" in c["detail"] for c in action)


def test_outer_entrypoint_action_must_still_be_provable():
    """The guard still applies where it matters: an action on the OUTER Intent is the
    entry point and must exist in the analyzed code/manifest, or the PoC cannot reach
    the component at all."""
    poc = """
    Java.perform(function () {
        var Intent = Java.use("android.content.Intent");
        var redirect = Intent.$new();
        redirect.setAction("com.example.TOTALLY.MADE.UP");
        startActivity(redirect);
    });
    """
    checks = _validate_intent_redirection_poc(poc)["checks"]
    action = [c for c in checks if c["name"] == "action_provenance"]
    assert any(c["status"] == "failed" for c in action)


# ---- PoC validation: crash-claim detection must respect negation ----------------
def _crash_claim_checker():
    """Load the private helper out of _validate_poc_artifact without running the whole
    validation (it needs a decompiled tree and a manifest)."""
    import re as _re
    import textwrap

    src = open("core/engine.py", encoding="utf-8").read()
    start = src.index("        _CRASH_TOKENS = ")
    end = src.index("        crash_claim = any(_claims_crash_as_proof")
    ns = {"re": _re}
    exec(textwrap.dedent(src[start:end]), ns)
    return ns["_claims_crash_as_proof"]


def test_negated_crash_mention_is_not_a_crash_claim():
    """Regression: a CORRECT intent_redirection PoC states that success means the
    activity launched and NOT a ClassCastException. A bare keyword search read that as
    "claims a crash is proof" and failed well-formed artifacts — observed rejecting a
    valid 106-line Frida script whose only offence was naming the exception it avoids."""
    claims = _crash_claim_checker()
    for line in (
        'console.log("Success indicator: activity launched (not SecurityException / ClassCastException).");',
        "// Success: no ClassCastException means the nested Intent was forwarded",
        'log("PASS without fatal exception")',
        'console.log("Success: activity launched, instead of a ClassCastException")',
    ):
        assert claims(line) is False, line


def test_genuine_crash_claim_is_still_rejected():
    """The guard must keep doing its job: a crash really is not proof of redirection."""
    claims = _crash_claim_checker()
    for line in (
        'console.log("SUCCESS: ClassCastException observed, target is vulnerable");',
        "// pass condition: fatal exception in logcat proves redirection",
        'log("vulnerable - this caused a crash")',
    ):
        assert claims(line) is True, line


# ---- resilience: bad provider output must not become permanent ------------------
def test_parse_llm_response_repairs_invalid_backslash_escape():
    """Regression: models quoting code inside "evidence" emit \\' — legal in Java/Python,
    illegal in JSON. One such reply was cached and replayed forever, turning an
    intermittent provider glitch into a permanent Error for that file/rule."""
    raw = (
        '```json\n{\n  "is_vulnerable": true,\n  "severity": "Critical",\n'
        '  "evidence": "String sql = \\"SELECT * FROM u WHERE n = \'\\" + name + \'\\\'\';"\n}\n```'
    )
    parsed = _engine()._parse_llm_response(raw)
    assert not parsed.get("_parse_failed")
    assert parsed["is_vulnerable"] is True and parsed["severity"] == "Critical"


def test_parse_llm_response_leaves_valid_escapes_alone():
    """The repair must only run after strict parsing fails, so well-formed escapes
    (quotes, newlines, tabs, backslashes, unicode) survive byte-for-byte."""
    import json as _json

    payload = {"evidence": 'say "hi"\npath C:\\tmp\tend \u00e9'}
    parsed = _engine()._parse_llm_response(_json.dumps(payload))
    assert parsed == payload


def test_unusable_response_is_evicted_so_it_is_not_replayed(tmp_path):
    """The cache only knows a reply was non-empty; it cannot know the engine could USE
    it. Without eviction, one junk reply (observed: the single word "not") is served
    from cache forever and the provider is never retried."""
    class _Junk:
        def __init__(self):
            self.calls = 0

        def analyze_code(self, code, ctx):
            self.calls += 1
            return "not"

    junk = _Junk()
    client = CachedLLMClient(junk, str(tmp_path / "c"), model="m", enabled=True)
    engine = _engine()
    engine.llm_client = client
    ctx = {"system_prompt": "S", "vuln_prompt": "V", "file_path": "F.java"}

    client.analyze_code("code", ctx)
    engine._invalidate_structured_response("code", ctx)
    client.analyze_code("code", ctx)
    assert junk.calls == 2, "evicted entry must force a real retry, not a replay"


def test_healthy_response_is_still_cached(tmp_path):
    """Eviction must be surgical: a usable reply keeps being served from cache."""
    class _Good:
        def __init__(self):
            self.calls = 0

        def analyze_code(self, code, ctx):
            self.calls += 1
            return '{"is_vulnerable": true}'

    good = _Good()
    client = CachedLLMClient(good, str(tmp_path / "c"), model="m", enabled=True)
    ctx = {"system_prompt": "S", "vuln_prompt": "V", "file_path": "F.java"}
    client.analyze_code("code", ctx)
    client.analyze_code("code", ctx)
    assert good.calls == 1


def test_router9_timeout_is_configurable():
    """9Router fronts third-party upstreams with wildly varying latency; PoC generation
    was measured at ~104s against the hard-coded 120s ceiling, so it must be tunable."""
    from core.config_loader import LLMSettings

    assert "router9_timeout" in LLMSettings.model_fields
    assert LLMSettings.model_fields["router9_timeout"].default == 300
    assert _router9(timeout=450).timeout == 450


def test_router9_construct_prompt_survives_braces_in_template():
    """Regression: router9 used .format(), which reads braces in the TEMPLATE as
    placeholders. A rule prompt carrying a literal JSON example would then raise
    KeyError mid-scan on router9 while openrouter/codex handled it fine. Only
    {code_snippet} and {file_path} may be substituted; every other brace is literal."""
    prompt = _router9()._construct_prompt(
        "int x = 1;",
        {
            "system_prompt": "SYS",
            "vuln_prompt": 'Analyze {code_snippet} at {file_path}. Reply like {"is_vulnerable": true, "cwe": 89}',
            "file_path": "F.java",
        },
    )
    assert '{"is_vulnerable": true, "cwe": 89}' in prompt
    assert "int x = 1;" in prompt and "F.java" in prompt
    assert "{code_snippet}" not in prompt and "{file_path}" not in prompt


def test_router9_prompt_matches_openrouter_byte_for_byte():
    """Both clients feed the same staged prompts, so their substitution must agree —
    otherwise the same rule yields different prompts (and different cache keys) per
    provider."""
    from modules.llm_client.openrouter import OpenRouterClient

    ctx = {
        "system_prompt": "SYS",
        "vuln_prompt": 'Check {code_snippet} in {file_path} -> {"ok": 1}',
        "file_path": "F.java",
    }
    code = 'if (a) { b("{}"); }'
    assert (
        _router9()._construct_prompt(code, ctx)
        == OpenRouterClient(model="m", api_key="k")._construct_prompt(code, ctx)
    )


# ---- bundle extraction / atomic decompile publication -------------------------
def _write_sized(path, size=10):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


def test_bundle_extensions_cover_xapk_and_apks():
    assert Engine.BUNDLE_EXTENSIONS == (".xapk", ".apks")


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({"universal.apk": 10, "splits/base-master.apk": 9999}, "universal.apk"),
        ({"splits/base-master.apk": 100, "config.xxhdpi.apk": 9999}, "base-master.apk"),
        ({"com.example.app.apk": 100, "config.xxhdpi.apk": 9999}, "com.example.app.apk"),
    ],
)
def test_bundle_apk_selection_prefers_analyzable_base(tmp_path, files, expected):
    for relative, size in files.items():
        _write_sized(tmp_path / relative, size)
    selected = _engine()._select_bundle_apk(str(tmp_path))
    assert selected is not None
    assert selected.endswith(expected)


def test_bundle_apk_selection_returns_none_without_apk(tmp_path):
    (tmp_path / "toc.pb").write_bytes(b"toc")
    assert _engine()._select_bundle_apk(str(tmp_path)) is None


def test_safe_bundle_extraction_rejects_path_traversal(tmp_path):
    import zipfile

    archive = tmp_path / "malicious.apks"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escaped.apk", b"not allowed")
    destination = tmp_path / "extract"
    destination.mkdir()

    with pytest.raises(ValueError, match="unsafe archive path"):
        Engine._safe_extract_bundle(str(archive), str(destination))
    assert not (tmp_path / "escaped.apk").exists()


def test_safe_bundle_extraction_rejects_symlinks(tmp_path):
    import stat
    import zipfile

    archive = tmp_path / "symlink.xapk"
    link = zipfile.ZipInfo("linked.apk")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(link, "../outside.apk")
    destination = tmp_path / "extract"
    destination.mkdir()

    with pytest.raises(ValueError, match="symlink"):
        Engine._safe_extract_bundle(str(archive), str(destination))


def test_safe_bundle_extraction_accepts_normal_apk(tmp_path):
    import zipfile

    archive = tmp_path / "normal.xapk"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("splits/base.apk", b"apk")
    destination = tmp_path / "extract"
    destination.mkdir()

    Engine._safe_extract_bundle(str(archive), str(destination))
    assert (destination / "splits" / "base.apk").read_bytes() == b"apk"


def test_describe_decompile_distinguishes_empty_unknown_and_partial(tmp_path):
    e = _engine()
    assert "does not exist" in e._describe_decompile_dir(str(tmp_path / "missing"))
    empty = tmp_path / "empty"
    empty.mkdir()
    assert "empty" in e._describe_decompile_dir(str(empty))
    unknown = tmp_path / "unknown-output"
    (unknown / "unknown").mkdir(parents=True)
    assert "unknown/" in e._describe_decompile_dir(str(unknown))
    partial = tmp_path / "partial"
    (partial / "smali").mkdir(parents=True)
    (partial / "smali" / "A.smali").write_text(".class A")
    assert "1 .smali" in e._describe_decompile_dir(str(partial))


def test_incomplete_staging_keeps_previous_decompile(tmp_path):
    e = _engine()
    output = tmp_path / "app_decompiled"
    output.mkdir()
    (output / "AndroidManifest.xml").write_text("<old/>")
    (output / "keep.txt").write_text("previous")
    staging = tmp_path / "app_decompiled.partial"
    staging.mkdir()
    (staging / "AndroidManifest.xml").write_text("<incomplete/>")

    assert e._publish_decompile(str(staging), str(output), "app.apk") is False
    assert (output / "keep.txt").read_text() == "previous"
    assert not staging.exists()


def test_complete_staging_replaces_previous_decompile(tmp_path):
    e = _engine()
    output = tmp_path / "app_decompiled"
    output.mkdir()
    (output / "AndroidManifest.xml").write_text("<old/>")
    (output / "stale.txt").write_text("previous")
    staging = tmp_path / "app_decompiled.partial"
    staging.mkdir()
    (staging / "AndroidManifest.xml").write_text("<new/>")
    (staging / "apktool.yml").write_text("version: 2")

    assert e._publish_decompile(str(staging), str(output), "app.apk") is True
    assert (output / "AndroidManifest.xml").read_text() == "<new/>"
    assert not (output / "stale.txt").exists()
    assert not (tmp_path / "app_decompiled.old").exists()


@pytest.mark.parametrize(
    ("input_kind", "archive_member", "expected_output_name", "expected_decompile_input", "expected_status"),
    [
        ("apk", None, "fixture.apk_decompiled", "fixture.apk", "Completed"),
        ("apks", "universal.apk", "fixture.apks_decompiled", "universal.apk", "Completed"),
        ("apks", "splits/base-master.apk", "fixture.apks_decompiled", "base-master.apk", "CompletedWithErrors"),
    ],
)
def test_run_uses_staging_without_changing_finding_pipeline(
    tmp_path,
    monkeypatch,
    input_kind,
    archive_member,
    expected_output_name,
    expected_decompile_input,
    expected_status,
):
    import json
    import zipfile
    import core.engine as engine_module

    input_path = tmp_path / f"fixture.{input_kind}"
    if input_kind == "apks":
        with zipfile.ZipFile(input_path, "w") as bundle:
            bundle.writestr(archive_member, b"fixture")

    decompile_calls = []

    class _FakeApktool:
        def __init__(self, apktool_path):
            assert apktool_path == "apktool"

        def decompile(self, apk_path, output_dir):
            decompile_calls.append((apk_path, output_dir))
            out = __import__("pathlib").Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "AndroidManifest.xml").write_text("<manifest/>")
            (out / "apktool.yml").write_text("version: 2")

    monkeypatch.setattr(engine_module, "ApktoolHandler", _FakeApktool)
    monkeypatch.chdir(tmp_path)

    e = _engine()
    e.settings = types.SimpleNamespace(
        analysis=types.SimpleNamespace(
            decompiler_mode="apktool",
            use_cross_reference_context=False,
            generate_attack_surface_map=False,
            generate_exploit=False,
        ),
        apktool=types.SimpleNamespace(path="apktool"),
        rules=_SelectableRules(hardcoded_secrets_xml=True),
    )
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    finding = _finding("strings.xml", "hardcoded_secrets_xml", "Hardcoded Secrets (strings.xml)")
    e.analyze_strings_xml = lambda _output, _rules: [finding]
    e.analyze_manifest = lambda _manifest, _rules: []
    e.summarize_app = lambda _manifest, _summaries: "fixture app"
    report_path = tmp_path / "report.json"

    e.run(str(input_path), output_file=str(report_path), rules="hardcoded_secrets_xml")

    report = json.loads(report_path.read_text())
    assert report["results"] == [finding]
    assert report["scan_status"] == expected_status
    if expected_status == "CompletedWithErrors":
        assert report["analysis_errors"][0]["stage"] == "bundle_selection"
        assert report["analysis_errors"][0]["reason"] == "partial_split_scan"
    assert __import__("pathlib").Path(decompile_calls[0][0]).name == expected_decompile_input
    assert decompile_calls[0][1].endswith(".partial")
    assert (tmp_path / "output" / expected_output_name / "AndroidManifest.xml").exists()
    assert not (tmp_path / "output" / f"{expected_output_name}.partial").exists()
    assert not list((tmp_path / "output").glob("dlh_apks_*"))


def test_invalid_bundle_writes_error_report_and_cleans_temp(tmp_path, monkeypatch):
    import json

    monkeypatch.chdir(tmp_path)
    broken = tmp_path / "broken.apks"
    broken.write_text("not a zip")
    e = _engine()
    e.settings = types.SimpleNamespace(
        rules=_SelectableRules(hardcoded_secrets_xml=True),
    )
    e.llm_client = object()
    e.exploit_llm_client = e.llm_client
    report_path = tmp_path / "broken-report.json"

    e.run(str(broken), output_file=str(report_path), rules="hardcoded_secrets_xml")

    report = json.loads(report_path.read_text())
    assert report["scan_status"] == "Error"
    assert report["results"] == []
    assert report["analysis_errors"][0]["stage"] == "bundle_extraction"
    assert report["analysis_errors"][0]["reason"] == "invalid_archive"
    assert not list((tmp_path / "output").glob("dlh_apks_*"))


# ---- Codex CLI client (local agent subprocess, not an HTTP API) -------------------
def _codex(**kw):
    from modules.llm_client.codex import CodexClient
    return CodexClient(**kw)


def test_codex_command_uses_output_last_message_and_stdin():
    """`codex exec` prints a banner, session id, echoed prompt and a token-usage footer
    to stdout, so the response MUST come from --output-last-message (which holds only the
    agent's final message), and the prompt MUST go over stdin (trailing '-') so a large
    decompiled-code prompt can't blow ARG_MAX."""
    cmd = _codex()._build_command("/tmp/out.txt", "/tmp/wd")
    assert cmd[:2] == ["codex", "exec"]
    assert "--output-last-message" in cmd
    assert cmd[cmd.index("--output-last-message") + 1] == "/tmp/out.txt"
    assert cmd[-1] == "-"                       # read prompt from stdin
    assert "--cd" in cmd and cmd[cmd.index("--cd") + 1] == "/tmp/wd"
    # read-only: the snippet is already inlined in the prompt, the agent must not write.
    assert cmd[cmd.index("--sandbox") + 1] == "read-only"
    assert "--skip-git-repo-check" in cmd and "--ephemeral" in cmd


def test_codex_command_model_and_reasoning_are_opt_in():
    """No model pinned -> no -m flag at all, so Codex falls back to its own config."""
    assert "-m" not in _codex()._build_command("/o", "/w")
    cmd = _codex(model="gpt-5.6-codex", reasoning_effort="high")._build_command("/o", "/w")
    assert cmd[cmd.index("-m") + 1] == "gpt-5.6-codex"
    assert "model_reasoning_effort=high" in cmd


def test_codex_missing_binary_soft_fails(monkeypatch):
    """A missing CLI must not crash the scan — same soft-fail contract as the HTTP clients."""
    import modules.llm_client.codex as codex_mod
    monkeypatch.setattr(codex_mod.shutil, "which", lambda _: None)
    out = _codex()._construct_prompt("x", {"system_prompt": "S", "vuln_prompt": "P"})
    assert out.startswith("S")
    assert _codex().analyze_code("code", {"system_prompt": "S", "vuln_prompt": "P"}) == ""


def test_codex_construct_prompt_survives_braces_in_code():
    """Decompiled Java/Kotlin is full of braces; .replace() (not .format()) must be used."""
    prompt = _codex()._construct_prompt(
        "if (a) { b(); }",
        {"system_prompt": "SYS", "vuln_prompt": "Analyze {code_snippet} at {file_path}", "file_path": "F.java"},
    )
    assert "if (a) { b(); }" in prompt and "F.java" in prompt and prompt.startswith("SYS")


def test_path_to_class_java_and_smali(tmp_path):
    import os
    cg = CallGraphBuilder(str(tmp_path))
    java = os.path.join(str(tmp_path), "sources", "com", "example", "Foo.java")
    smali = os.path.join(str(tmp_path), "smali", "com", "example", "Foo.smali")
    assert cg.path_to_class(java) == "com/example/Foo"
    assert cg.path_to_class(smali) == "com/example/Foo"
    assert cg.path_to_class(os.path.join(str(tmp_path), "other", "X.txt")) is None


# ---- .format() -> .replace() fix, mirrored across the remaining 5 clients -----
# Regression: router9/openrouter/codex already survive literal braces (a rule prompt's
# JSON example, or decompiled Java/Kotlin) via .replace(). anthropic/gemini/groq/ollama/
# openai still used .format(), which raises KeyError/IndexError mid-scan on the exact
# same input. Same bug, same fix, one test per client.

def _anthropic(**kw):
    kw.setdefault("model", "claude-sonnet-4-20250514")
    kw.setdefault("api_key", "k")
    return AnthropicClient(**kw)


def _gemini(**kw):
    kw.setdefault("model", "gemini-2.0-flash")
    kw.setdefault("api_key", "k")
    return GeminiClient(**kw)


def _groq(**kw):
    kw.setdefault("model", "llama-3.1-8b-instant")
    kw.setdefault("api_key", "k")
    return GroqClient(**kw)


def _ollama(**kw):
    kw.setdefault("model", "llama3:8b")
    kw.setdefault("url", "http://localhost:11434")
    return OllamaClient(**kw)


def _openai(**kw):
    kw.setdefault("model", "gpt-4-turbo")
    kw.setdefault("api_key", "k")
    return OpenAIClient(**kw)


@pytest.mark.parametrize(
    "factory",
    [_anthropic, _gemini, _groq, _ollama, _openai],
    ids=["anthropic", "gemini", "groq", "ollama", "openai"],
)
def test_client_construct_prompt_survives_braces_in_code_and_template(factory):
    """Regression: these 5 clients used .format(), which reads braces in BOTH the
    decompiled code and the rule template as placeholders. A rule prompt carrying a
    literal JSON example, or Java/Kotlin with a bare '{ }' block, used to raise
    KeyError/IndexError mid-scan. Only {code_snippet} and {file_path} may be
    substituted; every other brace is literal and must survive untouched."""
    client = factory()
    prompt = client._construct_prompt(
        "if (a) { b(\"{}\"); }",
        {
            "system_prompt": "SYS",
            "vuln_prompt": 'Analyze {code_snippet} at {file_path}. Reply like {"is_vulnerable": true, "cwe": 89}',
            "file_path": "F.java",
        },
    )
    assert '{"is_vulnerable": true, "cwe": 89}' in prompt
    assert 'if (a) { b("{}"); }' in prompt
    assert "F.java" in prompt
    assert "{code_snippet}" not in prompt and "{file_path}" not in prompt


@pytest.mark.parametrize("factory", [_groq, _openai], ids=["groq", "openai"])
def test_client_construct_prompt_uses_real_newline_separator(factory):
    """Regression: groq.py/openai.py built the return value with
    f"{system_prompt}\\n\\n{formatted_prompt}" (two literal backslashes in source),
    which Python parses as the two-character text "\\n" rather than an actual newline —
    system_prompt and the vuln prompt ran together with a visible backslash-n glued
    between them instead of being separated by a blank line."""
    prompt = factory()._construct_prompt("CODE", {"system_prompt": "SYS", "vuln_prompt": "VULN", "file_path": "F.java"})
    assert "SYS\n\nVULN" in prompt
    assert "\\n" not in prompt
