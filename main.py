import argparse
import sys
import subprocess
import os

def run_cli(query, num_results):
    print(f"[*] Starting Domain Hunter CLI...")
    print(f"[*] Query: '{query}' | Number of Searches: {num_results}")
    
    # 1. Search
    print(f"\n[1/3] Searching...")
    res = subprocess.run([sys.executable, "searcher.py", query, "-n", str(num_results)], capture_output=False)
    if res.returncode != 0:
        print("[-] Searcher script failed.")
        sys.exit(1)
        
    # 2. Crawl
    print(f"\n[2/3] Crawling and extracting domains...")
    res = subprocess.run([sys.executable, "crawler.py"], capture_output=False)
    if res.returncode != 0:
        print("[-] Crawler script failed.")
        sys.exit(1)
        
    # 3. Check
    print(f"\n[3/3] Checking DNS & WHOIS registration status...")
    res = subprocess.run([sys.executable, "checker.py"], capture_output=False)
    if res.returncode != 0:
        print("[-] Checker script failed.")
        sys.exit(1)
        
    print("\n[+] Domain Hunter execution completed successfully!")
    print("[+] Expired/Available results saved to: expired_domains.json")
    print("[+] Detailed Markdown report generated at: expired_domains.md")

def run_ui():
    print("[*] Launching Streamlit Web Dashboard...")
    # Find streamlit path or run via module
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])
    except KeyboardInterrupt:
        print("\n[*] Stopping Streamlit...")

def main():
    parser = argparse.ArgumentParser(description="Domain Hunter Pro - Crawl Google searches and discover expired domains.")
    parser.add_argument("-q", "--query", type=str, help="Search query (CLI mode)")
    parser.add_argument("-n", "--num", type=int, default=20, help="Number of search results to crawl (default: 20)")
    parser.add_argument("--ui", action="store_true", help="Launch Streamlit Web UI dashboard")
    
    args = parser.parse_args()
    
    if args.ui or (not args.query):
        # Default to UI mode if --ui is specified or if no query is provided via CLI
        run_ui()
    else:
        run_cli(args.query, args.num)

if __name__ == "__main__":
    main()
