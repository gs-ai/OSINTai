import os
from .storage import write_json

def write_report(run_dir: str, ranked_pages: list):
    out_txt = os.path.join(run_dir, "report.txt")
    lines = []
    lines.append("OSINTai Report")
    lines.append("=" * 60)
    for i, p in enumerate(ranked_pages[:25], start=1):
        lines.append(f"{i:02d}. score={p.get('score')}  {p.get('url')}")
        if p.get("title"):
            lines.append(f"    title: {p.get('title')}")
        if p.get("summary"):
            lines.append(f"    summary: {p.get('summary')}")
        rf = p.get("risk_flags") or []
        if isinstance(rf, list) and rf:
            lines.append(f"    risk_flags: {', '.join([str(x) for x in rf])[:220]}")
        lines.append("")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    write_json(os.path.join(run_dir, "ranked_pages.json"), ranked_pages)
    return out_txt