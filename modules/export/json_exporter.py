from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Union

DISCLAIMER = "Templates only. No request sending. Authorized use only."


def export_payloads_to_json(
    payloads: List[Dict[str, Any]],
    out_path: Union[str, Path],
    tool_name: str = "task2-exporter",
    schema_version: str = "1.0",
    pretty: bool = True,
) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    doc = {
        "schema_version": schema_version,
        "generated_by": tool_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": DISCLAIMER,
        "count": len(payloads),
        "payloads": payloads,
    }

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2 if pretty else None)

    return out_path
