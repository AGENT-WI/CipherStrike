from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Set, Union


def export_burp_intruder_payloads(
    payloads: List[Dict[str, Any]],
    out_path: Union[str, Path],
    dedupe: bool = True,
    max_len: int = 8000,
) -> Path:
    """
    Burp Intruder payload file:
    - one payload per line
    - no metadata, no headers
    - flatten newlines
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    seen: Set[str] = set()
    out_lines: List[str] = []

    for p in payloads:
        raw = p.get("template") or ""
        s = raw.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
        if not s:
            continue

        # Flatten any multiline payload to single line
        s = " ".join(s.splitlines()).strip()

        if not s or len(s) > max_len:
            continue

        if dedupe:
            if s in seen:
                continue
            seen.add(s)

        out_lines.append(s)

    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out_lines) + ("\n" if out_lines else ""))

    return out_path
