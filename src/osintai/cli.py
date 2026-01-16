import os
import argparse
import json
import asyncio

from osintai.storage import safe_mkdir, now_run_id, load_lines
from osintai.extractor import Extractor
from osintai.proxy_pool import ProxyPool
from osintai.fetcher import AsyncFetcher
from osintai.crawler import AsyncCrawler
from osintai.scoring import rank_pages
from osintai.report import write_report

def _read_jsonl(path: str):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except:
                pass
    return rows

def main():
    ap = argparse.ArgumentParser(description="OSINTai v3.2 FULL (async + proxy + dedupe + embeddings + hunt + graph export)")
    ap.add_argument("--seed", help="Seed URL (or use seed_urls.txt file)")
    ap.add_argument("--depth", type=int, default=2, help="Max depth")
    ap.add_argument("--max", type=int, default=150, help="Max URLs")
    ap.add_argument("--same-domain", action="store_true", help="Only crawl same domain as seed")

    ap.add_argument("--concurrency", type=int, default=18, help="Global concurrency")
    ap.add_argument("--per-host", type=int, default=4, help="Per-host concurrency")

    ap.add_argument("--ua", default="user_agents.txt", help="User agents file")
    ap.add_argument("--proxies", default="", help="Optional proxy list file")

    ap.add_argument("--model", default="granite3.2:latest", help="Ollama analyze model")
    ap.add_argument("--embed-model", default="nomic-embed-text:latest", help="Ollama embeddings model")
    ap.add_argument("--no-ollama", action="store_true", help="Disable LLM analysis and embeddings")

    ap.add_argument("--hunt", default="", help="Comma-separated hunt terms")
    ap.add_argument("--hunt-max", type=int, default=50, help="Max lead URLs per page from hunt mode")

    ap.add_argument("--run-id", default="", help="Optional run id override")
    args = ap.parse_args()

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    
    # Handle seed URLs - check file first, then command line
    seed_urls = []
    seed_file = os.path.join(base_dir, "OSINTai_FILES1", "seeds", "seed_urls.txt")
    
    if os.path.exists(seed_file):
        file_seeds = load_lines(seed_file)
        if file_seeds:
            seed_urls = [url.strip() for url in file_seeds if url.strip() and url.strip().startswith(('http://', 'https://'))]
    
    # If no seeds from file, use command line argument
    if not seed_urls:
        if not args.seed:
            ap.error("No seed URLs found. Provide --seed URL or add URLs to OSINTai_FILES1/seeds/seed_urls.txt")
        seed_urls = [args.seed]
    
    print(f"Found {len(seed_urls)} seed URL(s):")
    for url in seed_urls[:5]:  # Show first 5
        print(f"  - {url}")
    if len(seed_urls) > 5:
        print(f"  ... and {len(seed_urls) - 5} more")
    print()

    run_id = args.run_id.strip() or now_run_id()
    run_dir = os.path.join(base_dir, "data", "runs", run_id)
    safe_mkdir(run_dir)

    user_agents = load_lines(os.path.join(base_dir, args.ua))
    proxies = load_lines(args.proxies) if args.proxies else []
    proxy_pool = ProxyPool(proxies) if proxies else None

    fetcher = AsyncFetcher(
        user_agents=user_agents,
        proxy_pool=proxy_pool,
        timeout_s=20.0,
        min_delay_s=0.2,
        max_delay_s=1.2,
        retries=2
    )

    extractor = Extractor()
    hunt_terms = [t.strip() for t in (args.hunt.split(",") if args.hunt else []) if t.strip()]

    crawler = AsyncCrawler(
        seed_urls=seed_urls,
        max_depth=args.depth,
        max_urls=args.max,
        run_dir=run_dir,
        fetcher=fetcher,
        extractor=extractor,
        same_domain_only=args.same_domain,
        resume=True,
        concurrency=args.concurrency,
        per_host_concurrency=args.per_host,
        use_ollama=(not args.no_ollama),
        model_analyze=args.model,
        model_embed=args.embed_model,
        hunt_terms=hunt_terms,
        hunt_max_leads=args.hunt_max
    )

    print("")
    print("=" * 80)
    print("OSINTai v3.2 FULL")
    print(f"RUN DIR: {run_dir}")
    print(f"SEEDS: {len(seed_urls)} URL(s)")
    if len(seed_urls) == 1:
        print(f"SEED: {seed_urls[0]}")
    else:
        print(f"PRIMARY SEED: {seed_urls[0]}")
        print(f"ADDITIONAL SEEDS: {len(seed_urls) - 1}")
    print(f"DEPTH: {args.depth}  MAX_URLS: {args.max}  SAME_DOMAIN: {args.same_domain}")
    print(f"CONCURRENCY: {args.concurrency}  PER_HOST: {args.per_host}")
    print(f"OLLAMA: {'OFF' if args.no_ollama else args.model}")
    print(f"EMBED:  {'OFF' if args.no_ollama else args.embed_model}")
    print(f"HUNT:   {', '.join(hunt_terms) if hunt_terms else 'OFF'}")
    print("=" * 80)
    print("")

    out = asyncio.run(crawler.crawl())

    page_scores = _read_jsonl(out["page_scores_jsonl"])
    ranked = rank_pages(page_scores)
    report_path = write_report(run_dir, ranked)

    print("")
    print("DONE.")
    print(f"- URLs:         {out['urls_jsonl']}")
    print(f"- Indicators:   {out['indicators_jsonl']}")
    print(f"- Scores:       {out['page_scores_jsonl']}")
    if os.path.exists(out.get("hunt_jsonl","")):
        print(f"- Hunt:         {out['hunt_jsonl']}")
    print(f"- Graph nodes:  {out['graph_nodes']}")
    print(f"- Graph edges:  {out['graph_edges']}")
    print(f"- Report:       {report_path}")
    print("")

if __name__ == "__main__":
    main()
