import streamlit as st
import sys
# Self-healing: if time module was globally corrupted, reload it from scratch
if 'time' in sys.modules:
    try:
        import importlib
        importlib.reload(sys.modules['time'])
    except Exception:
        pass
import time
import pandas as pd
import json
import os
import datetime
import sys
import threading
import queue
import logging
from urllib.parse import urlparse

# Import modular components for in-process execution and real-time UI updates
import searcher
import crawler
import checker

# Force reload project modules to ensure latest changes on disk are used
try:
    import importlib
    importlib.reload(searcher)
    importlib.reload(crawler)
    importlib.reload(checker)
except Exception:
    pass

# Page Configuration
st.set_page_config(
    page_title="Domain Hunter Pro",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Premium Styling
st.markdown("""
<style>
    /* Global Styles */
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=Space+Grotesk:wght@400;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    /* Header Gradient & Typography */
    .title-container {
        background: linear-gradient(135deg, #1f4068 0%, #162447 50%, #0f1a1c 100%);
        padding: 2.5rem;
        border-radius: 20px;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        border: 1px solid rgba(255, 255, 255, 0.05);
        position: relative;
        overflow: hidden;
    }
    .title-container::after {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle, rgba(0,212,255,0.08) 0%, transparent 60%);
        pointer-events: none;
    }
    .main-title {
        font-family: 'Space Grotesk', sans-serif;
        font-weight: 800;
        font-size: 3.5rem;
        background: linear-gradient(to right, #00d4ff, #00ffaa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        letter-spacing: -1px;
    }
    .subtitle {
        font-size: 1.2rem;
        color: #a0aec0;
        margin-top: 0.5rem;
        font-weight: 300;
    }
    
    /* Custom Cards (Glassmorphism) */
    .metric-card {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.05);
        border-radius: 16px;
        padding: 1.5rem;
        text-align: center;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
        transition: transform 0.3s ease, border-color 0.3s ease;
    }
    .metric-card:hover {
        transform: translateY(-5px);
        border-color: rgba(0, 212, 255, 0.3);
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: 700;
        font-family: 'Space Grotesk', sans-serif;
        color: #00d4ff;
        margin-bottom: 0.25rem;
    }
    .metric-label {
        font-size: 0.95rem;
        color: #718096;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }
    
    /* Terminal Console Style */
    .terminal-container {
        background-color: #090d16;
        border: 1px solid #1a2035;
        border-radius: 12px;
        padding: 1.2rem;
        font-family: 'Courier New', Courier, monospace;
        color: #00ffaa;
        height: 300px;
        overflow-y: auto;
        box-shadow: inset 0 0 20px rgba(0,0,0,0.6);
        font-size: 0.9rem;
        line-height: 1.4;
    }
    .terminal-line {
        margin-bottom: 4px;
    }
    .terminal-info { color: #00d4ff; }
    .terminal-success { color: #00ffaa; }
    .terminal-warning { color: #ffaa00; }
    .terminal-error { color: #ff5555; }
    
    /* Status Badge styling */
    .badge {
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
    }
    .badge-available { background-color: rgba(0, 255, 170, 0.15); color: #00ffaa; border: 1px solid rgba(0, 255, 170, 0.3); }
    .badge-expired { background-color: rgba(255, 85, 85, 0.15); color: #ff5555; border: 1px solid rgba(255, 85, 85, 0.3); }
    .badge-redemption { background-color: rgba(255, 170, 0, 0.15); color: #ffaa00; border: 1px solid rgba(255, 170, 0, 0.3); }
    .badge-inactive { background-color: rgba(113, 128, 150, 0.15); color: #a0aec0; border: 1px solid rgba(113, 128, 150, 0.3); }
</style>
""", unsafe_allow_html=True)

# Application Header
st.markdown("""
<div class="title-container">
    <h1 class="main-title">🌐 DOMAIN HUNTER PRO</h1>
    <div class="subtitle">Extract authority backlinks & discover unregistered or expired domains in real-time.</div>
</div>
""", unsafe_allow_html=True)

# Core State Initialization
if "pipeline_state" not in st.session_state:
    st.session_state.pipeline_state = {
        "active": False,
        "log_queue": queue.Queue(),
        "terminal_logs": [],
        "search_results": [],
        "found_domains": [],
        "expired_domains": [],
        "metrics": {
            "search_urls": 0,
            "domains_found": 0,
            "available_domains": 0,
            "expired_domains": 0,
            "execution_time": 0.0
        }
    }

# Logging Redirect Hook
class UIStreamHandler:
    def __init__(self, log_queue):
        self.log_queue = log_queue
    def write(self, message):
        msg = message.strip()
        if msg:
            self.log_queue.put(msg)
    def flush(self):
        pass

# Sidebar Configurations
st.sidebar.markdown("### ⚙️ Search Configuration")
query = st.sidebar.text_input("Google Search Query", placeholder="e.g. tech startups blog list", help="Enter a search term to find relevant articles.")
num_searches = st.sidebar.slider("Top Search Results Limit", min_value=5, max_value=50, value=20, step=5, help="Number of Google/DuckDuckGo links to extract.")

st.sidebar.markdown("### 🕷️ Crawler Settings")
crawl_timeout = st.sidebar.slider("Crawl Timeout (seconds)", min_value=3, max_value=25, value=10, step=1, help="Max time to wait for a site response.")

st.sidebar.markdown("### 🔍 Verification Settings")
dns_workers = st.sidebar.slider("DNS Threads", min_value=5, max_value=50, value=20, step=5, help="Parallel threads for checking active domains.")
whois_workers = st.sidebar.slider("WHOIS Threads", min_value=1, max_value=5, value=3, step=1, help="Parallel threads for looking up expired/available domains (low concurrency avoids rate limits).")
pacing_delay = st.sidebar.slider("WHOIS Pacing Delay (s)", min_value=0.5, max_value=3.0, value=1.2, step=0.1, help="Delay between consecutive WHOIS queries per thread to prevent blocking.")

st.sidebar.markdown("---")
start_hunt = st.sidebar.button("🚀 Start Hunting", type="primary", use_container_width=True, disabled=st.session_state.pipeline_state["active"])
if st.session_state.pipeline_state["active"]:
    st.sidebar.info("Hunting process is currently active...")

# Main Layout
tab_dashboard, tab_results, tab_system = st.tabs(["📊 Dashboard & Progress", "🎯 Expired/Available Domains", "🛠️ System Logs"])

# Real-Time Logger Drain Function
def drain_logs():
    q = st.session_state.pipeline_state["log_queue"]
    while not q.empty():
        line = q.get()
        # Decorate based on contents
        if "[INFO]" in line or "Fetching:" in line or "Querying" in line:
            decorated = f"<span class='terminal-info'>[INFO]</span> {line.split(']', 1)[-1] if ']' in line else line}"
        elif "[WARNING]" in line:
            decorated = f"<span class='terminal-warning'>[WARN]</span> {line.split(']', 1)[-1] if ']' in line else line}"
        elif "[ERROR]" in line or "failed" in line.lower():
            decorated = f"<span class='terminal-error'>[ERR]</span> {line.split(']', 1)[-1] if ']' in line else line}"
        elif "Successfully" in line or "Finished" in line:
            decorated = f"<span class='terminal-success'>[SUCCESS]</span> {line.split(']', 1)[-1] if ']' in line else line}"
        else:
            decorated = line
        st.session_state.pipeline_state["terminal_logs"].append(decorated)

# Hunting Pipeline Implementation
def run_pipeline(state, query, num_searches, crawl_timeout, dns_workers, whois_workers, pacing_delay):
    try:
        t0 = time.time()
        # Configure local logger capture
        log_handler = UIStreamHandler(state["log_queue"])
        searcher.logger.handlers = [logging.StreamHandler(log_handler)]
        crawler.logger.handlers = [logging.StreamHandler(log_handler)]
        
        # Step 1: Search the Web
        state["log_queue"].put("[INFO] Pipeline started. Initiating search...")
        urls = []
        try:
            urls = searcher.search_google(query, num_searches)
        except Exception as e:
            state["log_queue"].put(f"[WARNING] Google search failed: {e}")
            
        if not urls:
            state["log_queue"].put("[WARNING] Google returned 0 results. Executing DuckDuckGo fallback...")
            try:
                urls = searcher.search_duckduckgo(query, num_searches)
            except Exception as e:
                state["log_queue"].put(f"[ERROR] DuckDuckGo search failed: {e}")
                
        if not urls:
            state["log_queue"].put("[ERROR] Web search yielded zero results. Exiting pipeline.")
            state["active"] = False
            return
            
        state["search_results"] = urls
        state["log_queue"].put(f"[SUCCESS] Search completed. Found {len(urls)} URLs.")
        state["metrics"]["searched_urls"] = len(urls)
        
        # Step 2: Crawl target URLs
        state["log_queue"].put("[INFO] Initiating external link extraction...")
        found_domains = {}
        
        # Patch crawl function custom headers and timeout
        for idx, url in enumerate(urls):
            state["log_queue"].put(f"[INFO] Crawling page {idx+1}/{len(urls)}: {url}")
            try:
                crawler.crawl_url(url, found_domains)
            except Exception as e:
                state["log_queue"].put(f"[WARNING] Failed crawling {url}: {e}")
                
        # Save unique external domains with their sources
        output_data = []
        for domain in sorted(found_domains.keys()):
            output_data.append({
                "domain": domain,
                "sources": sorted(list(found_domains[domain]))
            })
            
        state["found_domains"] = output_data
            
        sorted_domains = sorted(list(found_domains.keys()))
            
        state["log_queue"].put(f"[SUCCESS] Crawling completed. Extracted {len(sorted_domains)} unique domains.")
        state["metrics"]["domains_found"] = len(sorted_domains)
        
        # Step 3: Verify Domain Expiration/Availability
        if not sorted_domains:
            state["log_queue"].put("[WARNING] No external domains extracted. Skipping verification.")
            state["active"] = False
            return
            
        state["log_queue"].put(f"[INFO] Launching parallel DNS verification (Threads: {dns_workers})...")
        non_resolving_domains = []
        resolving_count = 0
        
        with checker.concurrent.futures.ThreadPoolExecutor(max_workers=dns_workers) as executor:
            future_to_domain = {executor.submit(checker.check_dns, dom): dom for dom in sorted_domains}
            for future in checker.concurrent.futures.as_completed(future_to_domain):
                dom = future_to_domain[future]
                try:
                    resolves = future.result()
                    if resolves:
                        resolving_count += 1
                    else:
                        non_resolving_domains.append(dom)
                except Exception as e:
                    state["log_queue"].put(f"[WARNING] DNS lookup failed for {dom}: {e}")
                    non_resolving_domains.append(dom)
                    
        state["log_queue"].put(f"[INFO] DNS verify finished. {resolving_count} active, {len(non_resolving_domains)} inactive/non-resolving.")
        
        if not non_resolving_domains:
            state["log_queue"].put("[SUCCESS] All discovered domains are resolving. None are expired/available.")
            state["expired_domains"] = []
            state["active"] = False
            return
            
        state["log_queue"].put(f"[INFO] Launching WHOIS analysis for {len(non_resolving_domains)} domains (Threads: {whois_workers}, Pacing: {pacing_delay}s)...")
        results = []
        
        # Override WHOIS delay setting dynamically
        checker.WHOIS_DELAY = pacing_delay
        
        with checker.concurrent.futures.ThreadPoolExecutor(max_workers=whois_workers) as executor:
            future_to_whois = {executor.submit(checker.check_whois, dom): dom for dom in non_resolving_domains}
            for future in checker.concurrent.futures.as_completed(future_to_whois):
                dom = future_to_whois[future]
                try:
                    res = future.result()
                    results.append(res)
                    status_str = f"[{res['status'].upper()}]"
                    state["log_queue"].put(f"[INFO] Analyzed {dom} -> {status_str}")
                except Exception as e:
                    state["log_queue"].put(f"[ERROR] WHOIS failed for {dom}: {e}")
                    results.append({"domain": dom, "status": "error", "error": str(e), "available": False})
                    
        # Append sources to results
        for item in results:
            item["sources"] = sorted(list(found_domains.get(item["domain"], [])))

        expired_or_available = [r for r in results if r["status"] in ["available", "expired", "redemption"]]
        state["expired_domains"] = expired_or_available
        
        avail_count = sum(1 for r in expired_or_available if r["status"] == "available")
        exp_count = sum(1 for r in expired_or_available if r["status"] == "expired")
        
        state["metrics"]["available_domains"] = avail_count
        state["metrics"]["expired_domains"] = exp_count
        state["metrics"]["execution_time"] = time.time() - t0
        
        state["log_queue"].put(f"[SUCCESS] Domain search pipeline finished! Available: {avail_count}, Expired: {exp_count}")
        
    except Exception as ex:
        print(f"CRITICAL: Pipeline execution crashed: {ex}", file=sys.stderr)
        try:
            state["log_queue"].put(f"[ERROR] Pipeline execution crashed: {ex}")
        except Exception:
            pass
    finally:
        state["active"] = False

# Action Trigger
if start_hunt:
    if not query.strip():
        st.warning("Please specify a valid search query first.")
    else:
        st.session_state.pipeline_state["active"] = True
        st.session_state.pipeline_state["terminal_logs"] = []
        st.session_state.pipeline_state["search_results"] = []
        st.session_state.pipeline_state["found_domains"] = []
        st.session_state.pipeline_state["expired_domains"] = []
        st.session_state.pipeline_state["metrics"] = {
            "searched_urls": 0,
            "domains_found": 0,
            "available_domains": 0,
            "expired_domains": 0,
            "execution_time": 0.0
        }
        
        # Run pipeline in a separate thread so UI stays highly responsive
        pipeline_thread = threading.Thread(
            target=run_pipeline,
            args=(st.session_state.pipeline_state, query, num_searches, crawl_timeout, dns_workers, whois_workers, pacing_delay)
        )
        pipeline_thread.start()
        st.rerun()

# ----------------- TAB: DASHBOARD -----------------
with tab_dashboard:
    col_u, col_d, col_a, col_e = st.columns(4)
    with col_u:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{st.session_state.pipeline_state["metrics"]["searched_urls"]}</div>
            <div class="metric-label">Google Pages Crawled</div>
        </div>
        """, unsafe_allow_html=True)
    with col_d:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{st.session_state.pipeline_state["metrics"]["domains_found"]}</div>
            <div class="metric-label">Extracted Domains</div>
        </div>
        """, unsafe_allow_html=True)
    with col_a:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #00ffaa;">{st.session_state.pipeline_state["metrics"]["available_domains"]}</div>
            <div class="metric-label">Available Domains</div>
        </div>
        """, unsafe_allow_html=True)
    with col_e:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ff5555;">{st.session_state.pipeline_state["metrics"]["expired_domains"]}</div>
            <div class="metric-label">Expired / Pending Delete</div>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("### 💻 Live Crawler Console")
    
    # Render Console
    drain_logs()
    log_content = "".join(f"<div class='terminal-line'>{line}</div>" for line in st.session_state.pipeline_state["terminal_logs"])
    st.markdown(f"""
    <div class="terminal-container">
        {log_content if log_content else "<div class='terminal-line' style='color:#718096;'>System ready. Enter query and click 'Start Hunting' to begin...</div>"}
    </div>
    """, unsafe_allow_html=True)
    
    # Auto-rerun UI if crawler thread is running
    if st.session_state.pipeline_state["active"]:
        time.sleep(1)
        st.rerun()

# ----------------- TAB: RESULTS -----------------
with tab_results:
    st.markdown("### 🎯 Hunt Results")
    
    raw_results = st.session_state.pipeline_state.get("expired_domains", [])
    if raw_results:
        # Parse into a clean DataFrame
        df_rows = []
        for r in raw_results:
            dom = r["domain"]
            status = r["status"]
            exp = r.get("expiration_date") or "N/A"
            if exp != "N/A":
                try:
                    exp = exp.split("T")[0]
                except Exception:
                    pass
            
            sources = r.get("sources", [])
            sources_str = ", ".join(sources)
            
            df_rows.append({
                "Domain": dom,
                "Status": status.upper(),
                "Expiration Date": exp,
                "Found On": sources_str,
                "Register Search Link": f"https://www.namecheap.com/domains/registration/results/?domain={dom}"
            })
            
        df = pd.DataFrame(df_rows)
        
        # Search / Filter utilities
        search_filter = st.text_input("🔍 Filter results by domain extension or keyword", placeholder="e.g. .com or .net")
        status_filter = st.multiselect("Filter Statuses", options=["AVAILABLE", "EXPIRED", "REDEMPTION"], default=["AVAILABLE", "EXPIRED", "REDEMPTION"])
        
        if search_filter:
            df = df[df["Domain"].str.contains(search_filter.lower())]
        df = df[df["Status"].isin(status_filter)]
        
        st.dataframe(
            df,
            column_config={
                "Domain": st.column_config.TextColumn("Domain Name", width="medium"),
                "Status": st.column_config.TextColumn("Analysis Result"),
                "Expiration Date": st.column_config.TextColumn("Expiration"),
                "Found On": st.column_config.TextColumn("Found On Source Pages"),
                "Register Search Link": st.column_config.LinkColumn("Register Link", display_text="Check Namecheap")
            },
            use_container_width=True,
            hide_index=True
        )
        
        # Expose Download Option
        col_csv, col_json = st.columns(2)
        with col_csv:
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Results as CSV", data=csv_data, file_name="domain_hunter_results.csv", mime="text/csv", use_container_width=True)
        with col_json:
            json_data = json.dumps(raw_results, indent=4)
            st.download_button("📥 Download Raw JSON", data=json_data, file_name="domain_hunter_results.json", mime="application/json", use_container_width=True)
    else:
        st.info("No available or expired domains identified yet. Adjust settings or run a new search.")

# ----------------- TAB: SYSTEM -----------------
with tab_system:
    st.markdown("### 📂 Discovered Workspace Files (In-Memory)")
    files_col1, files_col2 = st.columns(2)
    with files_col1:
        st.markdown("#### Search Results")
        search_results = st.session_state.pipeline_state.get("search_results", [])
        if search_results:
            st.json(search_results)
        else:
            st.text("No search results yet.")
            
    with files_col2:
        st.markdown("#### Found Domains")
        found_domains = st.session_state.pipeline_state.get("found_domains", [])
        if found_domains:
            st.json(found_domains)
        else:
            st.text("No domains found yet.")
