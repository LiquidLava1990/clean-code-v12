"""Module discovery for the 3-layer pre-refactor harness.

Walks the repository under HARNESS_REPO_ROOT and yields DiscoveredModule
records for every importable Python source file. Discovery is generic --
no per-project scope list -- so the harness drops cleanly into any
codebase. Optional config in ``cc_harness/config.py`` lets a project add
extra known-external dependencies or skip basenames.

Skipped:
  - ``__pycache__/``, ``.venv/``, ``.git/``, ``site-packages/``, ``build/``,
    ``dist/``, ``node_modules/``, ``_archive/``
  - test files (``test_*.py`` / ``*_test.py``) and pytest's ``conftest.py``
  - any basename listed in ``SKIP_BASENAMES`` -- these execute on import
    (e.g. ``setup.py``, custom ``start_*.py`` scripts).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


# The harness lives at ``<repo>/tests/cc_harness/_discovery.py`` so the
# repo root is two parents up.
HARNESS_REPO_ROOT: Path = Path(__file__).resolve().parent.parent.parent

# Externals the harness gracefully skips when missing. Projects can extend
# this set in ``cc_harness/config.py`` with ``EXTRA_EXTERNAL_DEPS``.
KNOWN_EXTERNAL_DEPS: frozenset[str] = frozenset({
    # Web + HTTP
    "fastapi", "uvicorn", "starlette", "pydantic", "httpx", "aiohttp",
    "websockets", "requests", "urllib3",
    # Parsing + scraping
    "lxml", "bs4", "markdownify", "html2text", "pdfplumber", "readability",
    "feedparser", "tldextract", "playwright", "botright", "camoufox",
    "curl_cffi", "pydoll", "drissionpage", "headlessx", "selenium",
    "undetected_chromedriver", "fake_useragent", "browserforge",
    "cloudscraper", "tls_client", "ddgs", "pytrends",
    # Storage + queue
    "redis", "psycopg", "sqlalchemy", "alembic", "asyncpg", "aiosqlite",
    # ML + audio + image
    "torch", "torchaudio", "torchvision", "transformers", "ultralytics",
    "ollama", "PIL", "cv2", "numpy", "scipy", "soundfile", "librosa",
    "speech_recognition", "pyht",
    # Async + concurrency
    "anyio", "tenacity", "aiofiles",
    # Config + serialisation
    "yaml",  # PyYAML imports as 'yaml'
    "toml", "tomli", "tomllib", "msgpack", "orjson",
    # Misc
    "rich", "click", "typer",
})

# Basenames that execute side effects on import; the harness never imports
# them (snapshotting a started service would hang).
SKIP_BASENAMES: frozenset[str] = frozenset({
    "setup.py",
    "conftest.py",
    "start_service.py",
    "_healthcheck.py",
    "check_health.py",
    "check_all_releases.py",
    "_fix_unicode.py",
})

_SKIP_DIRS: frozenset[str] = frozenset({
    "__pycache__",
    ".venv",
    "venv",
    ".git",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "site-packages",
    "build",
    "dist",
    "node_modules",
    "_archive",
    ".cc",
    "target",
    # The harness itself lives under tests/cc_harness/ -- don't snapshot
    # the snapshotter, and don't try to import its helpers as repo
    # modules (they're already imported via the cc_harness package).
    "cc_harness",
    # Project tests are not part of the public refactor surface; skipping
    # them keeps the snapshot focused on production code.
    "tests",
})

# Project-local extension hooks (populated lazily from cc_harness/config.py
# when present). Kept out of the frozenset so projects can add entries
# without forking the helper.
_extra_externals: set[str] = set()
_extra_skips: set[str] = set()


def _load_project_config() -> None:
    """Pull optional ``EXTRA_EXTERNAL_DEPS`` / ``EXTRA_SKIP_BASENAMES``."""
    try:
        from . import config as _cfg  # type: ignore[import-not-found]
    except ImportError:
        return
    extra_ext = getattr(_cfg, "EXTRA_EXTERNAL_DEPS", ())
    extra_skip = getattr(_cfg, "EXTRA_SKIP_BASENAMES", ())
    _extra_externals.update(str(x) for x in extra_ext)
    _extra_skips.update(str(x) for x in extra_skip)


_load_project_config()


@dataclass(frozen=True)
class DiscoveredModule:
    """A single Python source unit the harness will try to import."""

    sys_path_root: Path
    dotted: str
    source: Path

    @property
    def id(self) -> str:
        """pytest-friendly id (used as test parameter id)."""
        return self.dotted


def _is_skipped_dir(part: str) -> bool:
    return part in _SKIP_DIRS


def _is_test_or_skip(name: str) -> bool:
    if name in SKIP_BASENAMES or name in _extra_skips:
        return True
    if name.startswith("test_") or name.endswith("_test.py"):
        return True
    return False


def _iter_py_files(root: Path) -> Iterator[Path]:
    """Yield every importable .py source file under ``root``."""
    for path in root.rglob("*.py"):
        parts = path.relative_to(root).parts
        if any(_is_skipped_dir(p) for p in parts):
            continue
        if _is_test_or_skip(path.name):
            continue
        yield path


def _dotted_name(source: Path, sys_path_root: Path) -> str:
    """Compute the dotted module path used to import ``source``."""
    rel = source.relative_to(sys_path_root)
    parts = list(rel.parts)
    if parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1][:-3]  # strip .py
    return ".".join(parts)


def _build_module(source: Path, sys_path_root: Path) -> DiscoveredModule | None:
    """Return a DiscoveredModule for ``source`` or ``None`` if invalid."""
    try:
        dotted = _dotted_name(source, sys_path_root)
    except ValueError:
        return None
    if not dotted:
        return None
    return DiscoveredModule(
        sys_path_root=sys_path_root, dotted=dotted, source=source,
    )


def discover() -> list[DiscoveredModule]:
    """Return every module the harness should attempt to import."""
    sys_path_root = HARNESS_REPO_ROOT
    out: list[DiscoveredModule] = []
    seen: set[str] = set()
    for source in _iter_py_files(sys_path_root):
        module = _build_module(source, sys_path_root)
        if module is None or module.dotted in seen:
            continue
        seen.add(module.dotted)
        out.append(module)
    out.sort(key=lambda m: m.dotted)
    return out


def is_known_external(missing_module: str) -> bool:
    """True iff a missing-import name is a known external dependency."""
    head = missing_module.split(".", 1)[0]
    return head in KNOWN_EXTERNAL_DEPS or head in _extra_externals
