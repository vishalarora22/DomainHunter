import os
import sys
import json
import time
import datetime
import re
from urllib.parse import urlparse
import concurrent.futures
import socket

# Try importing dnspython and python-whois, handle import error if any
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


WHOIS_DELAY = 1.2

# Characters that can break out of Markdown table cells or inject content
_MD_UNSAFE = re.compile(r'[|`\[\]<>\r\n\\]')

def sanitize_md(value, max_len=200):
    """
    Strips characters that could break Markdown table formatting or inject HTML/links.
    Truncates to max_len as a safeguard against excessively long external strings.
    """
    if not isinstance(value, str):
        value = str(value)
    value = _MD_UNSAFE.sub('', value)
    return value[:max_len]


def safe_load_path(filepath, base_dir=None):
    """
    Resolves the filepath and ensures it stays within base_dir (defaults to CWD).
    Raises ValueError on path traversal attempts.
    """
    if base_dir is None:
        base_dir = os.path.abspath(os.getcwd())
    abs_path = os.path.abspath(filepath)
    if not abs_path.startswith(base_dir + os.sep) and abs_path != base_dir:
        raise ValueError(f"Path traversal detected: '{filepath}' is outside base directory '{base_dir}'")
    return abs_path


def clean_domain(domain_str):
    """Extract and clean the domain name from various string/URL inputs."""
    if not domain_str:
        return ""
    domain_str = domain_str.strip().lower()
    if "://" in domain_str:
        parsed = urlparse(domain_str)
        domain_str = parsed.netloc
    # Strip port if present
    if ":" in domain_str:
        domain_str = domain_str.split(":")[0]
    # Remove leading www. if present to avoid sub-domain lookup anomalies
    if domain_str.startswith("www."):
        domain_str = domain_str[4:]
    return domain_str


def load_domains(filepath):
    """
    Load domains from found_domains.json, supporting:
    - [{ "domain": "domain.com", "sources": [...] }] (new format)
    - list of strings/dicts (old format)
    Returns a dictionary mapping clean domain name to a list of source/referrer URLs.
    """
    # Validate path is within CWD (path traversal protection)
    try:
        filepath = safe_load_path(filepath)
    except ValueError as e:
        print(f"[-] Security error: {e}")
        return {}
    if not os.path.exists(filepath):
        # Create a mock found_domains.json if it doesn't exist
        mock_data = [
            {"domain": "google.com", "sources": ["https://example.com/mock1"]},
            {"domain": "github.com", "sources": ["https://example.com/mock2"]},
            {"domain": "microsoft.com", "sources": ["https://example.com/mock3"]},
            {"domain": "nonexistent-domain-test-12345abc.com", "sources": ["https://example.com/mock4"]},
            {"domain": "another-available-domain-999-xyz.net", "sources": ["https://example.com/mock5"]},
            {"domain": "wikipedia.org", "sources": ["https://example.com/mock6"]}
        ]
        print(f"[*] Input file '{filepath}' not found. Creating a mock file with test domains.")
        with open(filepath, 'w') as f:
            json.dump(mock_data, f, indent=4)
        return {d["domain"]: d["sources"] for d in mock_data}

    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[-] Error decoding JSON from {filepath}: {e}")
        return {}

    domain_map = {}
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                d = clean_domain(item)
                if d:
                    domain_map[d] = []
            elif isinstance(item, dict):
                d = clean_domain(item.get("domain", ""))
                if d:
                    domain_map[d] = item.get("sources", [])
                else:
                    for key in ['url', 'name', 'host']:
                        if key in item and isinstance(item[key], str):
                            d = clean_domain(item[key])
                            if d:
                                domain_map[d] = []
                            break
    elif isinstance(data, dict):
        for key, val in data.items():
            d = clean_domain(key)
            if d:
                if isinstance(val, list):
                    domain_map[d] = val
                elif isinstance(val, dict):
                    domain_map[d] = val.get("sources", [])
                else:
                    domain_map[d] = []

    return domain_map


def check_dns(domain):
    """
    Checks if a domain resolves using dnspython or socket.
    Returns True if domain resolves, False otherwise.
    """
    # 1. Try using dnspython if available
    if HAS_DNSPYTHON:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.0
            # Try A record first
            resolver.resolve(domain, 'A')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Check NS record in case A is not set but domain is active
            try:
                resolver.resolve(domain, 'NS')
                return True
            except Exception:
                pass
        except Exception:
            pass

    # 2. Fallback to standard socket resolution
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        try:
            # Fallback to getaddrinfo (which checks other protocols/records)
            socket.getaddrinfo(domain, None)
            return True
        except Exception:
            return False
    except Exception:
        return False


def parse_expiration_date(exp_date):
    """Parse python-whois expiration date format which can be a datetime, list, or string."""
    if not exp_date:
        return None
    if isinstance(exp_date, list):
        dates = [d for d in exp_date if isinstance(d, datetime.datetime)]
        if dates:
            return dates[0]
        return None
    if isinstance(exp_date, datetime.datetime):
        return exp_date
    return None


def check_status_for_redemption(status):
    """Check if WHOIS status list/string indicates redemption or pending delete."""
    if not status:
        return False
    if isinstance(status, str):
        status_list = [status]
    elif isinstance(status, list):
        status_list = status
    else:
        status_list = []

    for s in status_list:
        if not isinstance(s, str):
            continue
        s_lower = s.lower()
        if "redemption" in s_lower or "pendingdelete" in s_lower or "pending delete" in s_lower:
            return True
    return False

def check_whois_raw(domain):
    """
    Perform a raw TCP socket query to the appropriate WHOIS server.
    Returns a status dict if it can confidently verify availability, or raises an exception.
    """
    tld = domain.split(".")[-1].lower()
    
    # Common TLD WHOIS servers
    tld_servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "ca": "whois.cira.ca",
        "info": "whois.afilias.net",
        "biz": "whois.nic.biz",
        "co": "whois.nic.co",
        "us": "whois.nic.us",
        "uk": "whois.nic.uk",
        "io": "whois.nic.io",
        "me": "whois.nic.me",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "it": "whois.nic.it",
        "nl": "whois.domain-registry.nl",
        "ru": "whois.tcinet.ru",
        "cn": "whois.cnnic.cn",
        "jp": "whois.jprs.jp"
    }
    
    server = tld_servers.get(tld, "whois.iana.org")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((server, 43))
        
        # Format query: Verisign expects "domain\r\n", CIRA expects just "domain\r\n"
        query = f"{domain}\r\n"
        s.sendall(query.encode("utf-8"))
        
        # Receive response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
            if len(response) > 65536:  # Limit download size
                break
                
        s.close()
        
        response_text = response.decode("utf-8", errors="ignore")
        response_lower = response_text.lower()
        
        # Key phrases indicating domain is available
        availability_keywords = [
            "domain status: available",   # CIRA (.ca)
            "not found",
            "no match for",
            "no entries found",
            "no data found",
            "not registered",
            "domain status: free",
            "status: available",
            "status: free",
            "is free",
            "nothing found"
        ]
        
        for kw in availability_keywords:
            if kw in response_lower:
                return {
                    "domain": domain,
                    "status": "available",
                    "expiration_date": None,
                    "whois_status": "raw_socket_verified_available",
                    "available": True
                }
                
        # Clean response string to extract expiration date if registered
        exp_date = None
        for line in response_text.splitlines():
            line_lower = line.lower()
            if "expiry" in line_lower or "expiration" in line_lower or "expires" in line_lower:
                if ":" in line:
                    val = line.split(":", 1)[1].strip()
                    exp_date = val
                    break
                    
        return {
            "domain": domain,
            "status": "inactive",
            "expiration_date": exp_date,
            "whois_status": "raw_socket_verified_registered",
            "available": False
        }
        
    except Exception as e:
        raise Exception(f"Raw socket WHOIS failed for {domain} on server {server}: {e}")


def check_whois(domain):
    """
    Perform a WHOIS query to determine if the domain is:
    - Available (no WHOIS record found)
    - Expired (expiration date in the past)
    - In Redemption (status contains redemption/pendingdelete)
    - Inactive (registered, but DNS doesn't resolve, and not expired)
    - Error (rate limited or connection failure)
    """
    if not HAS_WHOIS:
        return {
            "domain": domain,
            "status": "error",
            "error": "python-whois library not installed",
            "available": False
        }

    # Add a pacing delay to mitigate rate limiting from registrar WHOIS servers
    time.sleep(WHOIS_DELAY)

    try:
        w = whois.whois(domain)
        
        # If no domain name was parsed at all, it might be available
        if not w.domain_name:
            return {
                "domain": domain,
                "status": "available",
                "expiration_date": None,
                "whois_status": None,
                "available": True
            }

        exp_date = parse_expiration_date(w.expiration_date)
        status = w.status

        is_exp = False
        is_redemption = False

        if exp_date:
            now = datetime.datetime.now(exp_date.tzinfo) if exp_date.tzinfo else datetime.datetime.now()
            if exp_date < now:
                is_exp = True

        if check_status_for_redemption(status):
            is_redemption = True

        if is_exp:
            return {
                "domain": domain,
                "status": "expired",
                "expiration_date": exp_date.isoformat() if exp_date else None,
                "whois_status": status,
                "available": False
            }
        elif is_redemption:
            return {
                "domain": domain,
                "status": "redemption",
                "expiration_date": exp_date.isoformat() if exp_date else None,
                "whois_status": status,
                "available": False
            }
        else:
            return {
                "domain": domain,
                "status": "inactive",
                "expiration_date": exp_date.isoformat() if exp_date else None,
                "whois_status": status,
                "available": False
            }

    except whois.exceptions.WhoisDomainNotFoundError:
        return {
            "domain": domain,
            "status": "available",
            "expiration_date": None,
            "whois_status": None,
            "available": True
        }
    except Exception as e:
        err_msg = str(e).lower()
        # Fallback keyword checks for unregistered domains
        if any(keyword in err_msg for keyword in ["no match for", "not found", "no data found", "not registered"]):
            return {
                "domain": domain,
                "status": "available",
                "expiration_date": None,
                "whois_status": None,
                "available": True
            }
        
        # If library throws an error (e.g. recursion error), fall back to raw socket query
        try:
            raw_res = check_whois_raw(domain)
            return raw_res
        except Exception as raw_e:
            return {
                "domain": domain,
                "status": "error",
                "error": f"whois_error: {e} | raw_socket_error: {raw_e}",
                "available": False
            }


def main():
    start_time = time.time()
    input_file = "found_domains.json"
    json_output_file = "expired_domains.json"
    md_output_file = "expired_domains.md"

    print("=" * 60)
    print(" Domain Checker Starting ")
    print("=" * 60)

    # 1. Load domains
    domain_map = load_domains(input_file)
    domains = list(domain_map.keys())
    total_domains = len(domains)
    print(f"[+] Loaded {total_domains} unique domains to check.")

    if not domains:
        print("[-] No domains found to check. Exiting.")
        return

    # 2. Parallel DNS Resolution
    print(f"\n[+] Resolving DNS in parallel (max 20 threads)...")
    non_resolving_domains = []
    resolving_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # Map domains to resolve futures
        future_to_domain = {executor.submit(check_dns, dom): dom for dom in domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            dom = future_to_domain[future]
            try:
                resolves = future.result()
                if resolves:
                    resolving_count += 1
                else:
                    non_resolving_domains.append(dom)
            except Exception as e:
                print(f"[-] DNS query error for {dom}: {e}")
                non_resolving_domains.append(dom)

    print(f"[+] DNS Check Completed: {resolving_count} resolving (active), {len(non_resolving_domains)} non-resolving.")

    if not non_resolving_domains:
        print("\n[+] All domains are active! No expired or available domains found.")
        # Write empty outputs to keep files consistent
        with open(json_output_file, 'w') as f:
            json.dump([], f, indent=4)
        generate_empty_md_report(md_output_file, total_domains, resolving_count)
        return

    # 3. Parallel WHOIS queries for non-resolving domains
    # We use fewer workers and backoff to avoid getting rate-limited by registry WHOIS servers.
    print(f"\n[+] Querying WHOIS for {len(non_resolving_domains)} non-resolving domains (max 3 threads with pacing delays)...")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_whois = {executor.submit(check_whois, dom): dom for dom in non_resolving_domains}
        for future in concurrent.futures.as_completed(future_to_whois):
            dom = future_to_whois[future]
            try:
                res = future.result()
                results.append(res)
                # Print status summary
                status_color = "[Available]" if res["status"] == "available" else f"[{res['status'].capitalize()}]"
                print(f"    - {dom}: {status_color}")
            except Exception as e:
                print(f"[-] WHOIS lookup execution error for {dom}: {e}")
                results.append({
                    "domain": dom,
                    "status": "error",
                    "error": str(e),
                    "available": False
                })

    # Append sources from domain_map to results
    for item in results:
        item["sources"] = domain_map.get(item["domain"], [])

    # 4. Filter expired, redemption, or available domains for the output reports
    # Registered/Inactive domains are excluded or categorized, but we focus on available, expired, and redemption domains.
    expired_or_available = [
        r for r in results if r["status"] in ["available", "expired", "redemption"]
    ]

    # Save to JSON
    with open(json_output_file, 'w') as f:
        json.dump(expired_or_available, f, indent=4)
    print(f"\n[+] Saved {len(expired_or_available)} expired/redemption/available domains to '{json_output_file}'.")

    # 5. Generate Markdown Report
    generate_md_report(
        filepath=md_output_file,
        total_checked=total_domains,
        resolving_count=resolving_count,
        non_resolving_results=results,
        expired_or_available=expired_or_available
    )
    print(f"[+] Saved summary report to '{md_output_file}'.")
    
    elapsed = time.time() - start_time
    print(f"\n[+] Done in {elapsed:.2f} seconds.")
    print("=" * 60)


def generate_empty_md_report(filepath, total_checked, resolving_count):
    """Generate markdown report when all domains are active."""
    with open(filepath, 'w') as f:
        f.write("# Domain Checker Summary Report\n\n")
        f.write(f"- **Total Checked**: {total_checked}\n")
        f.write(f"- **Active/Resolving**: {resolving_count}\n")
        f.write("- **Expired / Redemption / Available**: 0\n\n")
        f.write("All checked domains resolved successfully. No available or expired domains were identified.\n")


def format_sources_md(sources):
    """Formats a list of source/referrer URLs as compact markdown links."""
    if not sources:
        return "N/A"
    links = []
    for s in sources:
        try:
            parsed = urlparse(s)
            # Only allow http/https source URLs
            if parsed.scheme not in ("http", "https"):
                continue
            domain = parsed.netloc.lower().replace("www.", "")
            path = parsed.path
            if len(path) > 15:
                path = path[:12] + "..."
            label = sanitize_md(f"{domain}{path}", max_len=60)
            safe_url = sanitize_md(s, max_len=300)
            links.append(f"[{label}]({safe_url})")
        except Exception:
            links.append("[Link]")
    return ", ".join(links[:4]) + ("..." if len(links) > 4 else "")


def generate_md_report(filepath, total_checked, resolving_count, non_resolving_results, expired_or_available):
    """Generate detailed markdown summary report with tables and links."""
    # Group by status
    available_list = [r for r in expired_or_available if r["status"] == "available"]
    expired_list = [r for r in expired_or_available if r["status"] == "expired"]
    redemption_list = [r for r in expired_or_available if r["status"] == "redemption"]
    inactive_list = [r for r in non_resolving_results if r["status"] == "inactive"]
    error_list = [r for r in non_resolving_results if r["status"] == "error"]

    with open(filepath, 'w') as f:
        f.write("# Domain Checker Summary Report\n\n")
        f.write(f"- **Report Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **Total Domains Checked**: {total_checked}\n")
        f.write(f"- **Active/Resolving Domains**: {resolving_count}\n")
        f.write(f"- **Non-Resolving Domains Checked**: {len(non_resolving_results)}\n\n")

        f.write("## Summary Metrics\n\n")
        f.write("| Status | Count | Description |\n")
        f.write("| --- | --- | --- |\n")
        f.write(f"| **Available** | {len(available_list)} | No WHOIS record found (can be registered) |\n")
        f.write(f"| **Expired** | {len(expired_list)} | Expiration date has passed |\n")
        f.write(f"| **In Redemption** | {len(redemption_list)} | In redemption or pending delete status |\n")
        f.write(f"| **Inactive (Registered)** | {len(inactive_list)} | Does not resolve, but WHOIS record is active |\n")
        f.write(f"| **Check Error** | {len(error_list)} | WHOIS query failed (rate limits/network issues) |\n\n")

        # 1. Available Domains Table
        f.write("## Available Domains for Registration\n\n")
        if available_list:
            f.write("| Domain | Found On | Registration Search Link |\n")
            f.write("| --- | --- | --- |\n")
            for item in available_list:
                dom = sanitize_md(item["domain"])
                sources = format_sources_md(item.get("sources", []))
                search_url = f"https://www.namecheap.com/domains/registration/results/?domain={dom}"
                f.write(f"| `{dom}` | {sources} | [Search on Namecheap]({search_url}) |\n")
        else:
            f.write("*No available domains found.*\n")
        f.write("\n")

        # 2. Expired Domains Table
        f.write("## Expired Domains\n\n")
        if expired_list:
            f.write("| Domain | Expiration Date | Found On | Register Search |\n")
            f.write("| --- | --- | --- | --- |\n")
            for item in expired_list:
                dom = sanitize_md(item["domain"])
                exp = sanitize_md(item["expiration_date"] or "N/A")
                sources = format_sources_md(item.get("sources", []))
                search_url = f"https://www.namecheap.com/domains/registration/results/?domain={dom}"
                f.write(f"| `{dom}` | `{exp}` | {sources} | [Search]({search_url}) |\n")
        else:
            f.write("*No expired domains found.*\n")
        f.write("\n")

        # 3. Redemption/Pending Delete Domains Table
        f.write("## Domains in Redemption / Pending Delete\n\n")
        if redemption_list:
            f.write("| Domain | Expiration Date | Status / Details | Found On |\n")
            f.write("| --- | --- | --- | --- |\n")
            for item in redemption_list:
                dom = sanitize_md(item["domain"])
                exp = sanitize_md(item["expiration_date"] or "N/A")
                status = item["whois_status"]
                sources = format_sources_md(item.get("sources", []))
                status_str = status if isinstance(status, str) else ", ".join(status) if isinstance(status, list) else "N/A"
                status_str = sanitize_md(status_str, max_len=50)
                f.write(f"| `{dom}` | `{exp}` | `{status_str}` | {sources} |\n")
        else:
            f.write("*No domains in redemption/pending delete found.*\n")
        f.write("\n")

        # 4. Inactive (Registered but no DNS)
        f.write("## Inactive (Registered, No DNS resolution)\n\n")
        if inactive_list:
            f.write("| Domain | Expiration Date | Found On |\n")
            f.write("| --- | --- | --- |\n")
            for item in inactive_list:
                dom = sanitize_md(item["domain"])
                exp = sanitize_md(item["expiration_date"] or "N/A")
                sources = format_sources_md(item.get("sources", []))
                f.write(f"| `{dom}` | `{exp}` | {sources} |\n")
        else:
            f.write("*No inactive domains found.*\n")
        f.write("\n")

        # 5. Check Errors
        if error_list:
            f.write("## WHOIS Lookup Errors\n\n")
            f.write("| Domain | Error Detail | Found On |\n")
            f.write("| --- | --- | --- |\n")
            for item in error_list:
                sources = format_sources_md(item.get("sources", []))
                dom = sanitize_md(item['domain'])
                err = sanitize_md(item.get('error', 'Unknown Error'))
                f.write(f"| `{dom}` | `{err}` | {sources} |\n")
            f.write("\n")


if __name__ == "__main__":
    main()
