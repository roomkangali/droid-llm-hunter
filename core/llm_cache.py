import os
import hashlib
import tempfile
import threading
from typing import Dict, Any
from core import log


class CachedLLMClient:
    """
    [#4] Content-addressed cache wrapper around any LLM client.

    The cache key is a SHA-256 of (model + client fingerprint + system_prompt +
    vuln_prompt + code_snippet), so it is naturally correct: change the model, the rule
    prompt, or the analyzed code and the key changes -> the call re-runs. Identical
    inputs hit the cache.

    The "client fingerprint" covers per-client knobs that change the *answer* but live
    outside the prompt — without it those knobs are invisible to the cache. Concretely:
    Codex's `reasoning_effort` changes analysis depth, so a run at `low` followed by a
    run at `xhigh` used to return the cached `low` answer while never calling the model
    at `xhigh` (confirmed live). Any client may expose `cache_fingerprint() -> str`;
    clients that don't are unaffected, and an EMPTY fingerprint is skipped entirely so
    existing on-disk cache entries stay valid.

    This gives two things at once:
      - Resume: a scan that crashed or hit a rate limit re-uses every completed call
        on the next run instead of paying for it again.
      - Dedup: the same file summarized/analyzed twice costs one call.

    Only NON-EMPTY responses are cached. A failed call (empty string after retries, per
    the clients' soft-fail) is never stored, so a later resume retries it rather than
    permanently caching a failure as if it were a real answer.

    Unknown attribute access is delegated to the wrapped client, so this behaves like a
    drop-in replacement for the real client everywhere in the engine.
    """

    def __init__(self, client, cache_dir: str, model: str, enabled: bool = True):
        # Set via __dict__ to avoid triggering __getattr__ during init.
        self.__dict__["_state_lock"] = threading.RLock()
        self.__dict__["_key_locks"] = {}
        self.__dict__["_client"] = client
        self.__dict__["enabled"] = enabled
        self.__dict__["model"] = model or ""
        self.__dict__["cache_dir"] = cache_dir
        self.__dict__["hits"] = 0
        self.__dict__["misses"] = 0
        self.__dict__["errors"] = []
        if enabled:
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except Exception as e:
                log.warning(f"Could not create cache dir '{cache_dir}': {e}. Caching disabled.")
                self._record_error("initialize", cache_dir, "", e)
                self.__dict__["enabled"] = False

    def _record_error(self, operation: str, path: str, key: str, error: Exception):
        """Keep non-fatal cache failures observable to the scan report."""
        with self.__dict__["_state_lock"]:
            self.__dict__["errors"].append({
                "operation": operation,
                "path": path,
                "key": key,
                "detail": str(error),
            })

    def _increment(self, name: str):
        with self.__dict__["_state_lock"]:
            self.__dict__[name] += 1

    def _lock_for_key(self, key: str):
        """Return the process-local lock that serializes one content cache key."""
        with self.__dict__["_state_lock"]:
            return self.__dict__["_key_locks"].setdefault(key, threading.Lock())

    def _atomic_write(self, path: str, result: str):
        """Publish a complete cache entry atomically; never expose a partial file."""
        fd = None
        temporary_path = None
        try:
            fd, temporary_path = tempfile.mkstemp(
                prefix=f".{os.path.basename(path)}.",
                suffix=".tmp",
                dir=self.cache_dir,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as cache_file:
                fd = None
                cache_file.write(result)
            os.replace(temporary_path, path)
            temporary_path = None
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass

    def _client_fingerprint(self) -> str:
        """Output-affecting client settings that aren't part of the prompt.

        Optional and best-effort: a client that doesn't implement `cache_fingerprint`
        (or whose fingerprint raises) simply contributes nothing, which keeps this
        backward compatible with every existing client and with fakes used in tests.
        """
        fp = getattr(self._client, "cache_fingerprint", None)
        if not callable(fp):
            return ""
        try:
            return fp() or ""
        except Exception as e:
            log.warning(f"Could not read client cache fingerprint: {e}. Ignoring it.")
            self._record_error("fingerprint", self.cache_dir, "", e)
            return ""

    def _key(self, code_snippet: str, context: Dict[str, Any]) -> str:
        h = hashlib.sha256()
        parts = [self.model]
        fingerprint = self._client_fingerprint()
        if fingerprint:
            # Only mixed in when non-empty, so providers without a fingerprint keep the
            # keys they already have on disk and don't lose their cache on upgrade.
            parts.append(fingerprint)
        parts += [
            context.get("system_prompt", "") or "",
            context.get("vuln_prompt", "") or "",
            code_snippet or "",
        ]
        for part in parts:
            h.update(part.encode("utf-8", errors="replace"))
            h.update(b"\x00")
        return h.hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.txt")

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        if not self.enabled:
            return self._client.analyze_code(code_snippet, context)

        key = self._key(code_snippet, context)
        path = self._path(key)
        key_lock = self._lock_for_key(key)

        # Holding this lock across the underlying request intentionally deduplicates
        # same-key concurrent work. The context manager always releases it on timeout,
        # exception, or an empty response.
        with key_lock:
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        cached = f.read()
                    self._increment("hits")
                    log.debug(f"Cache HIT ({key[:12]}) for {context.get('file_path', 'N/A')}")
                    return cached
                except Exception as e:
                    log.debug(f"Cache read failed for {key[:12]}: {e}")
                    self._record_error("read", path, key, e)

            result = self._client.analyze_code(code_snippet, context)
            self._increment("misses")

            # Only persist successful responses so failures are retried on resume.
            if result and result.strip():
                try:
                    self._atomic_write(path, result)
                except Exception as e:
                    log.debug(f"Cache write failed for {key[:12]}: {e}")
                    self._record_error("write", path, key, e)

            return result

    def invalidate(self, code_snippet: str, context: Dict[str, Any]) -> bool:
        """Remove one exact cache entry after higher-level response validation fails.

        The key calculation is identical to ``analyze_code``. This is used by
        structured batch callers that can only determine a partial/invalid response
        after the provider has returned it; individual cache entries are untouched.
        """
        if not self.enabled:
            return False
        key = self._key(code_snippet, context)
        path = self._path(key)
        with self._lock_for_key(key):
            try:
                if os.path.exists(path):
                    os.unlink(path)
                    return True
            except Exception as e:
                log.debug(f"Cache invalidation failed for {key[:12]}: {e}")
                self._record_error("invalidate", path, key, e)
        return False

    def cache_stats(self) -> dict:
        with self.__dict__["_state_lock"]:
            return {
                "hits": self.hits,
                "misses": self.misses,
                "enabled": self.enabled,
                "errors": list(self.errors),
            }

    def __getattr__(self, name):
        # Only reached for attributes not found on this wrapper -> delegate to real client.
        return getattr(self.__dict__["_client"], name)
