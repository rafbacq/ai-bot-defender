"""Command-line entry point for the LLM querying pipeline.

Examples
--------
Offline demo against the bundled sample dataset (no API keys needed)::

    python -m querying.main --url https://example.com/ --models mock/scraper-sim mock/honest-llm

Against a locally-deployed honeypot site through the reverse proxy::

    python -m querying.main --site site-001 --local-base-domain dukecodeplus.localhost \
        --db-name scraper1-db --db-user user --models mock/scraper-sim

Run from the repository root so ``querying`` imports as a package.
"""

import argparse
import json

from . import config
from .pipeline import QueryRequest, run_query


def build_request(args):
    if args.site:
        host = f"{args.site}.{args.local_base_domain}"
        return QueryRequest(
            target_url=args.proxy_url,
            host_header=host,
            verify_tls=False,
            site_id=args.site,
            db_name=args.db_name,
            db_user=args.db_user,
            models=args.models,
            max_questions=args.max_questions,
            seed=args.seed,
        )
    return QueryRequest(
        target_url=args.url,
        models=args.models,
        csv_path=args.csv,
        max_questions=args.max_questions,
        seed=args.seed,
    )


def main():
    ap = argparse.ArgumentParser(description="AI Bot Defender — LLM querying pipeline")
    ap.add_argument("--url", help="Target URL to scrape (custom mode).")
    ap.add_argument("--site", help="Local honeypot site_id (proxy mode).")
    ap.add_argument("--proxy-url", default="http://127.0.0.1/",
                    help="Local proxy entry point for --site mode.")
    ap.add_argument("--local-base-domain", default="dukecodeplus.localhost")
    ap.add_argument("--db-name", help="Per-site DB name, e.g. scraper1-db.")
    ap.add_argument("--db-user", default="user", help="Per-site DB user.")
    ap.add_argument("--csv", default=str(config.SAMPLE_GROUND_TRUTH),
                    help="Ground-truth CSV for custom mode.")
    ap.add_argument("--models", nargs="+", default=["mock/scraper-sim", "mock/honest-llm"])
    ap.add_argument("--max-questions", type=int, default=config.MAX_PROBES)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    if not args.url and not args.site:
        ap.error("provide either --url (custom) or --site (local honeypot).")

    run = run_query(build_request(args))
    print(json.dumps(run, indent=2, default=str))


if __name__ == "__main__":
    main()
