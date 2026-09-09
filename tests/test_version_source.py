"""`__version__` is DERIVED from the distribution metadata, not typed.

── WHAT WAS MEASURED ───────────────────────────────────────────────────────────────────────

`coderifts.__version__` was the string "3.5.0" while pyproject.toml and PyPI both said 3.8.0. The
installed wheel reported a version three releases stale, and nothing failed — a hand-maintained
constant agrees with itself no matter how far it drifts from the thing it claims to describe.

This test exists because the DEFECT WAS SILENT. Anyone reading `__version__` to decide whether a
feature exists — a caller checking for the `[verify]` extra, a bug report, a support conversation —
was given a wrong answer by a package that was working correctly in every other respect.
"""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version as dist_version
from pathlib import Path

import pytest

import coderifts


def test_version_equals_the_installed_distribution_metadata():
    try:
        expected = dist_version("coderifts-sdk")
    except PackageNotFoundError:  # pragma: no cover
        pytest.skip("coderifts-sdk is not installed — the metadata comparison was NOT run "
                    "(not passed); install the package to check it")
    assert coderifts.__version__ == expected


def test_version_equals_pyproject():
    """The other end of the same chain.

    Metadata is BUILT from pyproject, so comparing against it too catches a stale wheel installed
    over a newer source — the state that produced the original defect.
    """
    text = Path(__file__).resolve().parent.parent.joinpath("pyproject.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert m, "pyproject.toml declares no version"
    try:
        dist_version("coderifts-sdk")
    except PackageNotFoundError:  # pragma: no cover
        pytest.skip("not installed — NOT RUN")
    assert coderifts.__version__ == m.group(1), (
        f"__version__ is {coderifts.__version__} and pyproject says {m.group(1)} — "
        "the installed distribution is stale against this source tree"
    )


def test_no_hand_maintained_version_literal_remains():
    """The shape, not just today's value.

    A test pinning the number passes until someone edits the number. This refuses the CONSTRUCT:
    a literal `__version__ = "x.y.z"` is how the drift happened, and it must not come back.
    """
    src = Path(coderifts.__file__).read_text()
    assert not re.search(r'^__version__\s*=\s*["\']\d', src, re.M), (
        "__version__ is a hand-typed literal again — derive it from importlib.metadata"
    )
    assert "importlib.metadata" in src


def test_a_bare_checkout_reports_an_unmistakable_placeholder(monkeypatch):
    """Absent metadata must not be reported as a release.

    Falling back to the last known number would be the original defect with extra steps.
    """
    import importlib
    import builtins
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "importlib.metadata":
            raise ImportError("no metadata here")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    reloaded = importlib.reload(coderifts)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        monkeypatch.setattr(builtins, "__import__", real_import)
        importlib.reload(coderifts)
