import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import csv
import time
from collections import deque
from playwright.sync_api import sync_playwright

# Known libraries regex patterns (extendable)
LIBRARY_PATTERNS = {
    "jQuery": [r"jquery[-.](\d+\.\d+\.\d+)"],
    "Bootstrap": [r"bootstrap[-.](\d+\.\d+\.\d+)"],
    "React": [r"react[-.](\d+\.\d+\.\d+)"],
    "AngularJS": [r"angular[-.](\d+\.\d+\.\d+)"],
    "Vue": [r"vue[-.](\d+\.\d+\.\d+)"],
    "Moment.js": [r"moment[-.](\d+\.\d+\.\d+)"],
    "Lodash": [r"lodash[-.](\d+\.\d+\.\d+)"],
}

def detect_from_filename(src_url: str):
    findings = []
    for lib, patterns in LIBRARY_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, src_url, re.IGNORECASE):
                findings.append(f"{lib} (maybe {src_url})")
    return findings

def detect_from_content(js_code: str):
    findings = []
    for lib, patterns in LIBRARY_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, js_code, re.IGNORECASE):
                findings.append(f"{lib} (content match)")
    return findings

def runtime_detection(page):
    findings = []
    # jQuery
    try:
        jq = page.evaluate("() => window.jQuery && jQuery.fn && jQuery.fn.jquery")
        if jq:
            findings.append(f"jQuery {jq} (runtime)")
    except Exception:
        pass
    # Bootstrap
    try:
        bs = page.evaluate("() => window.bootstrap && bootstrap.Tooltip && bootstrap.Tooltip.VERSION")
        if bs:
            findings.append(f"Bootstrap {bs} (runtime)")
    except Exception:
        pass
    # React
    try:
        react = page.evaluate("() => window.React && React.version")
        if react:
            findings.append(f"React {react} (runtime)")
    except Exception:
        pass
    # Angular
    try:
        ng = page.evaluate("() => window.angular && window.angular.version && window.angular.version.full")
        if ng:
            findings.append(f"AngularJS {ng} (runtime)")
    except Exception:
        pass
    # Vue
    try:
        vue = page.evaluate("() => window.Vue && Vue.version")
        if vue:
            findings.append(f"Vue {vue} (runtime)")
    except Exception:
        pass
    return findings

def crawl_and_detect(start_url, max_pages=50):
    visited = set()
    queue = deque([start_url])
    findings = []
    domain = urlparse(start_url).netloc

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()

        while queue and len(visited) < max_pages:
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            print(f"[{len(visited)}/{max_pages}] Visiting: {url}")

            try:
                resp = requests.get(url, timeout=10)
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
            except Exception as e:
                print(f"Request failed for {url}: {e}")
                continue

            # JS detection from <script>
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    abs_src = urljoin(url, src)
                    libs_from_filename = detect_from_filename(abs_src)
                    libs_from_content = []
                    try:
                        js_resp = requests.get(abs_src, timeout=5)
                        if js_resp.ok and "javascript" in js_resp.headers.get("Content-Type", ""):
                            libs_from_content = detect_from_content(js_resp.text[:5000])
                    except Exception:
                        pass
                    if libs_from_filename or libs_from_content:
                        findings.append({
                            "page_url": url,
                            "script_src": abs_src,
                            "lib_from_filename": ",".join(libs_from_filename),
                            "libs_from_content": ",".join(libs_from_content),
                            "runtime_libs": "",
                        })
                else:
                    inline_code = script.string or ""
                    libs_from_content = detect_from_content(inline_code)
                    if libs_from_content:
                        findings.append({
                            "page_url": url,
                            "script_src": "[inline]",
                            "lib_from_filename": "",
                            "libs_from_content": ",".join(libs_from_content),
                            "runtime_libs": "",
                        })

            # Runtime detection
            try:
                page = context.new_page()
                page.goto(url, timeout=15000)
                rt_libs = runtime_detection(page)
                if rt_libs:
                    findings.append({
                        "page_url": url,
                        "script_src": "[runtime]",
                        "lib_from_filename": "",
                        "libs_from_content": "",
                        "runtime_libs": ",".join(rt_libs),
                    })
                page.close()
            except Exception as e:
                print(f"Runtime detection failed for {url}: {e}")

            # Enqueue new internal links
            for a in soup.find_all("a", href=True):
                next_url = urljoin(url, a["href"])
                if urlparse(next_url).netloc == domain and next_url not in visited:
                    if next_url.startswith("http"):
                        queue.append(next_url)

            time.sleep(1)

        browser.close()

    return findings

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
            print(f"{row['page_url']} | filename_lib:{row['lib_from_filename'] or 'NONE'} "
                  f"| content_libs:{row['libs_from_content'] or 'NONE'} "
                  f"| runtime:{row['runtime_libs'] or 'NONE'} "
                  f"| src:{row['script_src'][:80]}")
    save_csv(findings)

if __name__ == "__main__":
    main()

