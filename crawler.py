import json
import logging
import sys
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

# Setup logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Set of domains to exclude (social networks, search engines, CDNs, system services, etc.)
EXCLUDED_DOMAINS = {
    # Social Media & Messaging
    "facebook.com", "twitter.com", "x.com", "linkedin.com", "instagram.com",
    "youtube.com", "pinterest.com", "reddit.com", "tiktok.com", "tumblr.com",
    "github.com", "githubusercontent.com", "medium.com", "t.co", "fb.me",
    "whatsapp.com", "telegram.org", "snapchat.com", "discord.com", "discord.gg",
    "slack.com", "vimeo.com", "flickr.com", "threads.net", "mastodon.social",
    
    # Search Engines & Tech Giants
    "google.com", "microsoft.com", "apple.com", "yahoo.com", "bing.com",
    "duckduckgo.com", "cloudflare.com", "amazon.com", "amazonaws.com",
    "adobe.com", "oracle.com", "android.com", "g.co", "youtu.be",
    
    # Common CDNs, Analytics, and Trackers
    "doubleclick.net", "googleadservices.com", "googletagmanager.com",
    "google-analytics.com", "googleapis.com", "gstatic.com", "optimizely.com",
    "hotjar.com", "sentry.io", "segment.io", "mixpanel.com", "disqus.com",
    "cloudfront.net", "fastly.net", "akamaihd.net", "gravatar.com", "wp.com",
}

def clean_domain(url_str):
    """
    Extracts and normalizes the domain name from a URL string.
    Returns None if the URL is invalid or does not have a HTTP/HTTPS scheme.
    """
    try:
        parsed = urlparse(url_str)
        if parsed.scheme not in ("http", "https"):
            return None
        
        netloc = parsed.netloc.lower()
        # Remove port if present
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        # Remove www. prefix if present
        if netloc.startswith("www."):
            netloc = netloc[4:]
            
        if not netloc or "." not in netloc:
            return None
            
        return netloc
    except Exception:
        return None

def is_excluded(domain):
    """
    Checks if a domain (or any of its parent domains) is in the EXCLUDED_DOMAINS set.
    """
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in EXCLUDED_DOMAINS:
            return True
    return False

def is_internal(source_domain, link_domain):
    """
    Checks if the link domain is internal relative to the source domain.
    Treats subdomains as internal (e.g., docs.python.org is internal to python.org).
    """
    if source_domain == link_domain:
        return True
    if link_domain.endswith("." + source_domain) or source_domain.endswith("." + link_domain):
        return True
    return False

def crawl_url(url, found_domains):
    """
    Fetches the URL, parses HTML using BeautifulSoup, filters links,
    and updates found_domains set with valid external domains.
    """
    source_domain = clean_domain(url)
    if not source_domain:
        logger.warning(f"Skipping invalid source URL: {url}")
        return

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    logger.info(f"Fetching: {url}")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return

    # Check content type to ensure it's HTML
    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        logger.warning(f"Skipping non-HTML page (Content-Type: {content_type}): {url}")
        return

    try:
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        logger.error(f"Error parsing HTML from {url}: {e}")
        return

    links_found = 0
    external_links_count = 0
    
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"].strip()
        if not href:
            continue
            
        links_found += 1
        # Resolve relative links using the source URL
        absolute_url = urljoin(url, href)
        link_domain = clean_domain(absolute_url)
        
        if not link_domain:
            continue
            
        # Filter out internal links
        if is_internal(source_domain, link_domain):
            continue
            
        # Filter out excluded social and system domains
        if is_excluded(link_domain):
            continue
            
        # If we got here, it's a valid external domain
        external_links_count += 1
        if isinstance(found_domains, dict):
            if link_domain not in found_domains:
                found_domains[link_domain] = set()
            found_domains[link_domain].add(url)
        else:
            found_domains.add(link_domain)

    logger.info(f"Finished crawling {url}. Found {links_found} total links, extracted {external_links_count} external domains.")
def normalize_url(url_str):
    """
    Normalizes a URL to help detect duplicates (e.g., desktop vs mobile Wikipedia, trailing slashes).
    """
    try:
        parsed = urlparse(url_str)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Normalize mobile subdomains (e.g., en.m.wikipedia.org -> en.wikipedia.org)
        parts = netloc.split(".")
        if len(parts) > 2 and parts[1] == "m":
            parts.pop(1)
            netloc = ".".join(parts)
            
        path = parsed.path.rstrip("/")
        # Discard query and fragment for deduplicating identical pages
        return f"{scheme}://{netloc}{path}"
    except Exception:
        return url_str

def main():
    try:
        with open("search_results.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("search_results.json not found in the current directory.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse search_results.json: {e}")
        sys.exit(1)

    # Robust URL extraction from search_results.json
    urls = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                urls.append(item)
            elif isinstance(item, dict):
                # Try common keys
                for key in ("url", "link", "href"):
                    if key in item and isinstance(item[key], str):
                        urls.append(item[key])
                        break
    elif isinstance(data, dict):
        # Maybe search results are structured as {"results": [...]} or similar
        for key in ("results", "urls", "items"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    if isinstance(item, str):
                        urls.append(item)
                    elif isinstance(item, dict) and "url" in item:
                        urls.append(item["url"])
        # If still empty, check if dict itself has a 'url' key
        if not urls and "url" in data and isinstance(data["url"], str):
            urls.append(data["url"])

    if not urls:
        logger.warning("No URLs found to crawl in search_results.json.")
        sys.exit(0)

    # Normalize and deduplicate URLs
    unique_urls = []
    seen_normalized = set()
    for url in urls:
        norm = normalize_url(url)
        if norm not in seen_normalized:
            seen_normalized.add(norm)
            unique_urls.append(url)

    logger.info(f"Extracted {len(urls)} URLs to crawl from search_results.json. Normalized down to {len(unique_urls)} unique pages.")
    
    found_domains = {}
    for url in unique_urls:
        crawl_url(url, found_domains)

    # Prepare structured output mapping domain -> list of source URLs
    output_data = []
    for domain in sorted(found_domains.keys()):
        output_data.append({
            "domain": domain,
            "sources": sorted(list(found_domains[domain]))
        })
    
    try:
        with open("found_domains.json", "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        logger.info(f"Successfully saved {len(output_data)} unique domains with their sources to found_domains.json.")
    except IOError as e:
        logger.error(f"Failed to write found_domains.json: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
