import argparse
import json
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("searcher.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("Searcher")

def search_google(query: str, num_results: int) -> list[str]:
    """
    Attempt to search Google using the googlesearch-python library.
    """
    logger.info(f"Querying Google for: '{query}' (limit: {num_results})")
    try:
        import googlesearch
        
        # Monkeypatch the user-agent generator to use a modern browser header
        # instead of the ancient Lynx user-agent, which is blocked by Google.
        googlesearch.get_useragent = lambda: (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        
        # googlesearch.search returns a generator of URLs
        results = list(googlesearch.search(query, num_results=num_results, sleep_interval=2))
        logger.info(f"Google search returned {len(results)} results.")
        return results
    except Exception as e:
        logger.warning(f"Google search failed or raised an exception: {e}")
        return []

def search_duckduckgo(query: str, num_results: int) -> list[str]:
    """
    Query DuckDuckGo as a fallback.
    """
    logger.info(f"Falling back to DuckDuckGo for: '{query}' (limit: {num_results})")
    try:
        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS
            
        with DDGS() as ddgs:
            results = ddgs.text(query, max_results=num_results)
            urls = [r["href"] for r in results if "href" in r]
            logger.info(f"DuckDuckGo search returned {len(urls)} results.")
            return urls
    except Exception as e:
        logger.error(f"DuckDuckGo search failed or raised an exception: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Search the web and write results to JSON.")
    parser.add_argument("query", type=str, help="Search query")
    parser.add_argument("-n", "--num", type=int, default=20, help="Number of results to return (default: 20)")
    args = parser.parse_args()
    
    # 1. Try Google Search
    urls = []
    try:
        urls = search_google(args.query, args.num)
    except Exception as e:
        logger.warning(f"Unexpected error during Google search: {e}")
        
    # 2. If Google returned no results (which is common when blocked or due to parser mismatch), fallback to DuckDuckGo
    if not urls:
        logger.info("Google returned 0 results. Proceeding with DuckDuckGo fallback...")
        try:
            urls = search_duckduckgo(args.query, args.num)
        except Exception as e:
            logger.error(f"Unexpected error during DuckDuckGo search: {e}")
            
    # 3. Write results to search_results.json
    output_path = "search_results.json"
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(urls, f, indent=4, ensure_ascii=False)
        logger.info(f"Successfully saved {len(urls)} URLs to {os.path.abspath(output_path)}")
    except Exception as e:
        logger.critical(f"Failed to write results to {output_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
