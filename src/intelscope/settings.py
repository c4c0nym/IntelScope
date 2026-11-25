"""Where IntelScope keeps API credentials and its tracker, and how credentials are looked up.

Lookup order for every credential field:

1. keys typed into the dashboard for this session only (held in memory, never written),
2. the local credentials file (``intelscope keys set`` or "Save on this computer" in the dashboard),
3. the environment, including a ``.env`` file.

The credentials file is plain JSON with owner-only permissions where the OS supports them.
It is as safe as the user profile it lives in, no safer: anyone who can read your files can read it.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


def _platform_dir(kind: str) -> Path:
    home = os.environ.get("INTELSCOPE_HOME")
    if home:
        return Path(home)
    if os.name == "nt":
        base = os.environ.get("APPDATA" if kind == "config" else "LOCALAPPDATA")
        fallback_dir = "Roaming" if kind == "config" else "Local"
        root = Path(base) if base else Path.home() / "AppData" / fallback_dir
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        if kind == "config":
            var, fallback = "XDG_CONFIG_HOME", ".config"
        else:
            var, fallback = "XDG_DATA_HOME", ".local/share"
        root = Path(os.environ.get(var) or Path.home() / fallback)
    return root / "intelscope"


def config_dir() -> Path:
    return _platform_dir("config")


def data_dir() -> Path:
    return _platform_dir("data")


def credentials_path() -> Path:
    return config_dir() / "credentials.json"


def tracker_path() -> Path:
    override = os.environ.get("INTELSCOPE_TRACKER")
    return Path(override) if override else data_dir() / "tracker.json"


def write_private(path: Path, text: str) -> None:
    """Atomic write; owner-only permissions where the OS has them."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        with contextlib.suppress(OSError):
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------- stored credentials

def load_stored() -> dict[str, dict[str, str]]:
    try:
        raw = json.loads(credentials_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for provider, fields in raw.items():
        if isinstance(provider, str) and isinstance(fields, dict):
            out[provider] = {str(k): str(v) for k, v in fields.items() if isinstance(v, str) and v}
    return out


def _save(data: dict[str, dict[str, str]]) -> None:
    write_private(credentials_path(), json.dumps(data, indent=2, sort_keys=True) + "\n")


def set_stored(provider: str, values: dict[str, str]) -> None:
    """Merge values into the file. An empty value removes that field."""
    data = load_stored()
    current = data.setdefault(provider, {})
    for name, value in values.items():
        if value:
            current[name] = value
        else:
            current.pop(name, None)
    if not current:
        data.pop(provider, None)
    _save(data)


def remove_stored(provider: str) -> bool:
    data = load_stored()
    if provider not in data:
        return False
    del data[provider]
    _save(data)
    return True


def resolve(provider: str, fields: Any, *layers: dict[str, dict[str, str]] | None) -> dict[str, str]:
    """Credential values for one provider: first layer that has the field wins, then the environment.

    `layers` are checked in order (pass the session layer first, the stored file second).
    """
    out: dict[str, str] = {}
    for f in fields:
        value = ""
        for layer in layers:
            value = ((layer or {}).get(provider) or {}).get(f.name, "")
            if value:
                break
        if not value and f.env:
            value = os.environ.get(f.env, "")
        if value:
            out[f.name] = value
    return out


def mask(value: str) -> str:
    """Enough of a secret to recognise it, never enough to use it."""
    if len(value) <= 8:
        return "•" * len(value)
    return "••••" + value[-4:]


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_value(value: str, kind: str = "secret") -> str:
    """Validate one credential value typed by a person."""
    value = value.strip()
    if _CTRL.search(value):
        raise ValueError("contains a control character")
    if len(value) > 2048:
        raise ValueError("is too long")
    if kind == "url" and value:
        if not re.match(r"https?://[^\s/]+", value, re.I):
            raise ValueError("must start with http:// or https://")
        value = value.rstrip("/")
    return value
