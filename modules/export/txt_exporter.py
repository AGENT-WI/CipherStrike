from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Union

DISCLAIMER_LINE = "# Templates only. Authorized testing only."


def export_payloads_to_txt(
    payloads: List[Dict[str, Any]],
    out_path: Union[str, Path],
    include_metadata: bool = True,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = [DISCLAIMER_LINE, ""]

    for p in payloads:
        template = (p.get("template") or "").replace("\r\n", "\n").rstrip("\n")
        if not template:
            continue

        if include_metadata:
            pid = p.get("id", "N/A")
            mod = p.get("module", "N/A")
            cat = p.get("category", "N/A")
            ctx = p.get("context", "N/A")
            tags = ", ".join(p.get("tags", []) or [])
            notes = (p.get("notes") or "").strip()

            lines.append(f"=== {pid} | module={mod} | category={cat} | context={ctx} ===")
            if tags:
                lines.append(f"tags: {tags}")
            if notes:
                lines.append(f"notes: {notes}")
            lines.append("template:")
            lines.append(template)
            lines.append("")
        else:
            lines.append(template)

    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).strip() + "\n")

    return out_path
