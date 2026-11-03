"""
Golden test — Layer 1 (deterministic, no LLM).

Validates that every rule's `detection_pattern` actually matches representative code
in the DEFAULT `hybrid` (JADX / Java) mode. This is the layer that catches "dead rule"
bugs where a Smali-only pattern never matches Java source (see the fragment_injection
regression below). It mirrors CodeFilter, which compiles patterns with no extra flags.
"""
import glob
import os
import re

import pytest
import yaml

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "prompts", "vuln_rules",
)


def _load(name):
    with open(os.path.join(RULES_DIR, name + ".yaml")) as f:
        return yaml.safe_load(f)


def _all_rules():
    return sorted(os.path.basename(p)[:-5] for p in glob.glob(os.path.join(RULES_DIR, "*.yaml")))


# Representative snippets each rule's detection_pattern MUST match.
# Java snippets reflect the default hybrid (JADX) mode; manifest rules use XML.
POSITIVE = {
    "biometric_bypass": "BiometricPrompt p = new BiometricPrompt(activity, exec, cb);",
    "deeplink_hijack": '<data android:scheme="myapp" android:host="open"/>',
    "deeplink_logic_bypass": 'String t = uri.getQueryParameter("token");',
    "exported_components": '<activity android:name=".A" android:exported="true"/>',
    "fragment_injection": "public class SettingsActivity extends PreferenceActivity {",
    "graphql_injection": 'String query = "query { user(id:1){name} }";',
    "hardcoded_secrets": 'String password = "hunter2";',
    "insecure_deserialization": "ObjectInputStream ois = new ObjectInputStream(is); ois.readObject();",
    "insecure_file_permissions": "openFileOutput(name, MODE_WORLD_READABLE);",
    "insecure_random_number_generation": "Random r = new Random();",
    "insecure_storage": 'getSharedPreferences("p", MODE_PRIVATE);',
    "insecure_webview": 'webView.addJavascriptInterface(new Bridge(), "app");',
    "intent_redirection": 'Intent fwd = (Intent) intent.getParcelableExtra("i"); startActivity(fwd);',
    "intent_spoofing": '<receiver android:name=".R" android:exported="true"/>',
    "jetpack_compose_security": "@Composable fun LoginScreen() {}",
    "library_vulnerability": "DexClassLoader cl = new DexClassLoader(path, opt, null, parent);",
    "path_traversal": "public ParcelFileDescriptor openFile(Uri uri, String mode) {",
    "pending_intent_hijacking": "PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_MUTABLE);",
    "sql_injection": 'db.rawQuery("SELECT * FROM u WHERE n=" + name, null);',
    "unsafe_reflection": 'Class.forName(intent.getStringExtra("cls"));',
    "webview_deeplink": '<action android:name="android.intent.action.VIEW"/>',
    "webview_file_access": "settings.setAllowFileAccess(true);",
    "webview_xss": "settings.setJavaScriptEnabled(true);",
    "zip_slip": "for (ZipEntry e : zip.entries()) { new File(dir, e.getName()); }",
}

# Rules that intentionally have NO detection_pattern (keyword-only / manifest heuristic /
# LLM-exclusive). universal_logic_flaw is LLM-exclusive (v1.3.0 T3.4a): no pattern so gating
# never skips a conceptual flaw.
NO_PATTERN = {"strandhogg", "hardcoded_secrets_xml", "universal_logic_flaw"}


def test_every_rule_has_golden_coverage():
    """If a new rule is added, force adding a snippet here (or listing it in NO_PATTERN)."""
    for rule in _all_rules():
        assert rule in POSITIVE or rule in NO_PATTERN, f"Rule '{rule}' has no golden coverage"


@pytest.mark.parametrize("rule", sorted(POSITIVE))
def test_detection_pattern_matches_sample(rule):
    data = _load(rule)
    pat = data.get("detection_pattern")
    assert pat, f"Rule '{rule}' is expected to have a detection_pattern"
    rx = re.compile(pat)  # mirrors CodeFilter (no external flags)
    assert rx.search(POSITIVE[rule]), (
        f"detection_pattern for '{rule}' does not match its default-mode sample: {POSITIVE[rule]!r}"
    )


def test_all_detection_patterns_compile():
    for rule in _all_rules():
        pat = _load(rule).get("detection_pattern")
        if pat:
            re.compile(pat)  # raises re.error if invalid


def test_all_rule_prompts_are_format_safe():
    """Every rule prompt must survive str.format(code_snippet=, file_path=) — no stray { } braces."""
    for rule in _all_rules():
        prompt = _load(rule).get("prompt", "")
        prompt.format(code_snippet="X", file_path="Y")  # raises KeyError/ValueError on stray braces


def test_fragment_injection_matches_both_java_and_smali():
    """Regression for the v1.2.0 [B] fix: this rule was Smali-only and dead in hybrid mode."""
    rx = re.compile(_load("fragment_injection")["detection_pattern"])
    assert rx.search("class X extends PreferenceActivity {"), "must match JADX/Java (default mode)"
    assert rx.search(".super Landroid/preference/PreferenceActivity;"), "must still match apktool/Smali"


@pytest.mark.parametrize("snippet", [
    # Existing signal forms must remain accepted.
    'Intent fwd = (Intent) intent.getParcelableExtra("forward");',
    'invoke-virtual {p0, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;',
    # Additive Bundle source coverage described by the rule prompt.
    'Intent fwd = bundle.getParcelable("forward");',
    'invoke-virtual {v0, v1}, Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;',
])
def test_intent_redirection_matches_existing_and_bundle_sources(snippet):
    rx = re.compile(_load("intent_redirection")["detection_pattern"])
    assert rx.search(snippet)


@pytest.mark.parametrize("rule,benign", [
    ("fragment_injection", "public class X extends Activity {"),
    ("sql_injection", "int total = a + b;"),
    ("insecure_random_number_generation", "int x = getRandomFromSecureSource();"),
    # v1.3.0 [D]: path_traversal no longer matches openFileOutput coincidentally
    ("path_traversal", 'openFileOutput("public.txt", MODE_PRIVATE);'),
    # v1.3.0 [D]: graphql no longer matches any "query = ..." assignment
    ("graphql_injection", 'String query = "SELECT * FROM users WHERE id=" + id;'),
])
def test_negative_cases_do_not_match(rule, benign):
    rx = re.compile(_load(rule)["detection_pattern"])
    assert not rx.search(benign), f"'{rule}' pattern should NOT match benign code: {benign!r}"


def test_path_traversal_matches_real_read_signal():
    """v1.3.0 [D]: path_traversal must match the real signal (FileInputStream/ContentProvider openFile)."""
    rx = re.compile(_load("path_traversal")["detection_pattern"])
    assert rx.search("FileInputStream in = new FileInputStream(new File(dir, name));")
    assert rx.search("FileOutputStream out = new FileOutputStream(target);")
    assert rx.search("public ParcelFileDescriptor openFile(Uri uri, String mode) {")


@pytest.mark.parametrize("snippet", [
    "File target = new File(baseDirectory, attackerControlledName);",
    "invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V",
])
def test_path_traversal_matches_file_constructor_java_and_smali(snippet):
    rx = re.compile(_load("path_traversal")["detection_pattern"])
    assert rx.search(snippet)


def test_path_traversal_prompt_keeps_canonical_and_allowlist_verdict_context():
    prompt = _load("path_traversal")["prompt"]
    assert "getCanonicalPath" in prompt
    assert "allowlist" in prompt


@pytest.mark.parametrize("snippet", [
    'db.rawQuery("SELECT * FROM users WHERE id=" + attacker, null);',
    'db.execSQL("DELETE FROM users WHERE id=" + attacker);',
    'db.query("users", columns, "name = " + attacker, null, null, null, null);',
])
def test_sql_injection_matches_existing_and_query_apis(snippet):
    rx = re.compile(_load("sql_injection")["detection_pattern"])
    assert rx.search(snippet)


def test_insecure_file_permissions_covers_setreadable():
    """v1.3.0 T2.2a: baseline gap — app uses File.setReadable(true, false), not MODE_WORLD_* constants."""
    rx = re.compile(_load("insecure_file_permissions")["detection_pattern"])
    assert rx.search("file.setReadable(true, false);")   # world-readable -> must match
    assert rx.search("f.setWritable(true, false)")       # world-writable -> must match
    assert not rx.search("file.setReadable(true, true);")  # owner-only -> safe, must NOT match
    assert not rx.search("file.setReadable(true);")        # single-arg -> safe, must NOT match


def test_pending_intent_matches_inlined_flag_mutable():
    """v2 Layer-2 finding: JADX inlines PendingIntent.FLAG_MUTABLE to its int value
    33554432, so the literal-only pattern missed PendingIntentActivity. The pattern must
    match both the named constant and the decompiled integer form."""
    rx = re.compile(_load("pending_intent_hijacking")["detection_pattern"], re.IGNORECASE | re.DOTALL)
    assert rx.search("PendingIntent pending = PendingIntent.getActivity(this, 0, baseIntent, 33554432);")
    assert rx.search("PendingIntent.getActivity(ctx, 0, i, PendingIntent.FLAG_MUTABLE);")
    # a non-mutable PendingIntent (immutable flag 67108864) must NOT match
    assert not rx.search("PendingIntent.getActivity(ctx, 0, i, 67108864);")


def test_pending_intent_matches_real_smali_flag_before_invocation():
    rx = re.compile(_load("pending_intent_hijacking")["detection_pattern"], re.IGNORECASE | re.DOTALL)
    smali = """
        const/high16 v3, 0x2000000
        invoke-static {p0, v1, v2, v3}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    """
    assert rx.search(smali)


def test_pending_intent_matches_legacy_mutable_without_immutable_flag():
    rx = re.compile(_load("pending_intent_hijacking")["detection_pattern"], re.IGNORECASE | re.DOTALL)
    assert rx.search("PendingIntent.getBroadcast(ctx, 0, intent, 0);")
    assert not rx.search("PendingIntent.getBroadcast(ctx, 0, intent, PendingIntent.FLAG_IMMUTABLE);")
    assert not rx.search("PendingIntent.getService(ctx, 0, intent, 67108864);")


def test_universal_logic_flaw_has_no_pattern():
    """v1.3.0 T3.4a: LLM-exclusive rule must have NO detection_pattern so gating never skips it."""
    assert not _load("universal_logic_flaw").get("detection_pattern")


# v1.3.0 T2.2: rules whose patterns were made dual-language must also match Smali (apktool mode).
SMALI_POSITIVE = {
    "unsafe_reflection": "invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
    "insecure_deserialization": "invoke-virtual {p0}, Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;",
    "pending_intent_hijacking": "Landroid/app/PendingIntent;->getActivity(...) sget Landroid/app/PendingIntent;->FLAG_MUTABLE:I",
    "zip_slip": "invoke-virtual {v1}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;",
}


@pytest.mark.parametrize("rule", sorted(SMALI_POSITIVE))
def test_detection_pattern_matches_smali_too(rule):
    rx = re.compile(_load(rule)["detection_pattern"])
    assert rx.search(SMALI_POSITIVE[rule]), f"'{rule}' should also match its Smali form (apktool mode)"
    # and still match Java (regression)
    assert rx.search(POSITIVE[rule]), f"'{rule}' must still match its Java form"
