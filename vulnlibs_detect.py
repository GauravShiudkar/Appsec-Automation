import requests
from urllib.parse import urljoin, urlparse
import re
import csv
import time
from collections import deque
from playwright.sync_api import sync_playwright
from packaging import version  # pip install packaging

# -------------------
# Library patterns
# -------------------
LIBRARY_PATTERNS = {
    "jQuery": [r"jQuery\.fn\.jquery\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", r"jQuery v(\d+\.\d+\.\d+)"],
    "Bootstrap": [r"bootstrap\.Tooltip\.VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]"],
    "React": [r"React\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", r"React\.createElement"],
    "AngularJS": [r"angular\.version\.full\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", r"angular\.module"],
    "Vue": [r"Vue\.version\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", r"Vue\.component"],
    "Moment.js": [r"moment\s*=\s*.*?(\d+\.\d+\.\d+)"],
    "Lodash": [r"lodash\.VERSION\s*=\s*['\"](\d+\.\d+\.\d+)['\"]", r"_\."],
}

# Latest versions (example)
LATEST_VERSIONS = {
    "jQuery": "3.7.1",
    "Bootstrap": "5.3.2",
    "React": "18.3.0",
    "AngularJS": "1.8.3",
    "Vue": "3.3.4",
    "Moment.js": "2.30.0",
    "Lodash": "4.17.21",
}

# Vulnerabilities (example, extendable)
VULNERABILITIES = {
    "jQuery": {"3.6.0": ["CVE-2022-1234"]},
    "Bootstrap": {"4.5.0": ["CVE-2020-0001"]},
    "React": {"17.0.1": ["CVE-2021-12345"]},
}

# -------------------
# Version & Vulnerability Checks
# -------------------
def check_outdated(lib_name, detected_version):
    latest = LATEST_VERSIONS.get(lib_name)
    if latest and detected_version:
        if version.parse(detected_version) < version.parse(latest):
            return f"Outdated (latest {latest})"
    return "Up-to-date"

def check_vulnerable(lib_name, detected_version):
    vulns = VULNERABILITIES.get(lib_name, {})
    return ",".join(vulns.get(detected_version, []))

# -------------------
# Detect libraries in JS content
# -------------------
def detect_from_content(js_code: str):
    findings = []
    vulnerabilities = []
    for lib, patterns in LIBRARY_PATTERNS.items():
        for pat in patterns:
            m = re.search(pat, js_code, re.IGNORECASE)
            if m:
                ver = m.group(1) if len(m.groups()) >= 1 else None
                status = check_outdated(lib, ver) if ver else "Detected"
                findings.append(f"{lib} {ver or ''} ({status})")
                if ver:
                    vuls = check_vulnerable(lib, ver)
                    if vuls:
                        vulnerabilities.append(f"{lib} {ver}: {vuls}")
                else:
                    # No version, just detected
                    vulnerabilities.append("")
    return findings, vulnerabilities

# -------------------
# Crawl & detect
# -------------------
def crawl_and_detect(start_url, max_pages=50):
    visited = set()
    queue = deque([start_url])
    results = []
    domain = urlparse(start_url).netloc

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)  # headless=True for normal use
        context = browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            print(f"[{len(visited)}/{max_pages}] Visiting: {url}")

            # Fetch HTML with requests
            try:
                resp = requests.get(url, timeout=10)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                html = resp.text
            except Exception as e:
                print(f"Request failed for {url}: {e}")
                continue

            # Parse <script> tags
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    abs_src = urljoin(url, src)
                    try:
                        js_resp = requests.get(abs_src, timeout=5)
                        if js_resp.ok and "javascript" in js_resp.headers.get("Content-Type", ""):
                            libs, vulns = detect_from_content(js_resp.text[:5000])
                            if libs:
                                results.append({
                                    "page_url": url,
                                    "script_src": abs_src,
                                    "libs_from_content": ",".join(libs),
                                    "runtime_libs": "",
                                    "vulnerabilities": ",".join(vulns),
                                })
                    except:
                        pass
                else:
                    inline_code = script.string or ""
                    libs, vulns = detect_from_content(inline_code)
                    if libs:
                        results.append({
                            "page_url": url,
                            "script_src": "[inline]",
                            "libs_from_content": ",".join(libs),
                            "runtime_libs": "",
                            "vulnerabilities": ",".join(vulns),
                        })

            # Runtime detection using network interception
            js_files = []

            def capture_js(request):
                if request.resource_type == "script":
                    js_files.append(request.url)

            try:
                page = context.new_page()
                page.on("request", capture_js)
                page.goto(url, timeout=60000, wait_until="networkidle")
                # Fetch JS files captured by network requests
                for js_url in js_files:
                    try:
                        js_resp = requests.get(js_url, timeout=5)
                        if js_resp.ok and "javascript" in js_resp.headers.get("Content-Type", ""):
                            libs, vulns = detect_from_content(js_resp.text[:5000])
                            if libs:
                                results.append({
                                    "page_url": url,
                                    "script_src": js_url,
                                    "libs_from_content": ",".join(libs),
                                    "runtime_libs": ",".join(libs),
                                    "vulnerabilities": ",".join(vulns),
                                })
                    except:
                        pass
                page.close()
            except Exception as e:
                print(f"Runtime detection failed for {url}: {e}")
                print("⚠️ Skipping runtime detection, continuing with script/inline detection.")

            # Enqueue new internal links
            for a in soup.find_all("a", href=True):
                next_url = urljoin(url, a["href"])
                if urlparse(next_url).netloc == domain and next_url not in visited:
                    if next_url.startswith("http"):
                        queue.append(next_url)

            time.sleep(1)

        browser.close()
    return results

# -------------------
# Save CSV
# -------------------
def save_csv(findings, filename="findings.csv"):
    if not findings:
        print("⚠️ No findings to save.")
        return
    keys = findings[0].keys()
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(findings)
    print(f"✅ Results saved to {filename}")

# -------------------
# Main
# -------------------
def main():
    start_url = input("Enter the starting URL (include https://): ").strip()
    if not start_url:
        print("No URL provided. Exiting.")
        return
    try:
        max_pages = int(input("Max pages to crawl (e.g. 50): ").strip() or "50")
    except ValueError:
        max_pages = 50

    print(f"Starting crawl at {start_url} (max pages={max_pages}). Ensure permission to scan this target.")
    findings = crawl_and_detect(start_url, max_pages=max_pages)
    if findings:
        print("\nSummary (first 30 rows):")
        for row in findings[:30]:
            print(f"{row['page_url']} | content_libs:{row['libs_from_content'] or 'NONE'} "
                  f"| runtime:{row['runtime_libs'] or 'NONE'} "
                  f"| vulnerabilities:{row['vulnerabilities'] or 'NONE'} "
                  f"| src:{row['script_src'][:80]}")
    save_csv(findings)

if __name__ == "__main__":
    main()
