import requests
import csv
from colorama import init, Fore, Style
from openpyxl import Workbook
from openpyxl.styles import Font
from urllib.parse import urljoin
from playwright.sync_api import sync_playwright

# Initialize colorama
init(autoreset=True)

# Headers to check
HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Access-Control-Allow-Origin",
    "X-Frame-Options",
    "X-XSS-Protection"
]

# Misconfiguration rules
MISCONFIG_RULES = {
    "Strict-Transport-Security": ["max-age=0"],
    "Content-Security-Policy": [""],
    "X-Content-Type-Options": ["nosniff"],
    "Access-Control-Allow-Origin": ["*"],
    "X-Frame-Options": ["ALLOWALL"],
    "X-XSS-Protection": ["0"]
}

# Secure header values to suggest
SECURE_HEADER_VALUES = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self';",
    "X-Content-Type-Options": "nosniff",
    "Access-Control-Allow-Origin": "Same Origin or specific domain",
    "X-Frame-Options": "SAMEORIGIN",
    "X-XSS-Protection": "1; mode=block"
}

def fetch_headers(url):
    try:
        response = requests.get(url, timeout=10)
        return response.headers
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return {}

def analyze_headers(url, headers):
    results = {"URL": url}
    suggested_values = []
    print(f"\n[+] Checking headers for: {url}")
    for header in HEADERS_TO_CHECK:
        value = headers.get(header, None)
        if not value:
            display = Fore.RED + "MISSING" + Style.RESET_ALL
            results[header] = "MISSING"
            suggested_values.append(f"{header}: {SECURE_HEADER_VALUES[header]}")
        elif header in MISCONFIG_RULES and any(bad_val.lower() in value.lower() for bad_val in MISCONFIG_RULES[header]):
            display = Fore.YELLOW + f"{value} (MISCONFIGURED)" + Style.RESET_ALL
            results[header] = f"{value} (MISCONFIGURED)"
            suggested_values.append(f"{header}: {SECURE_HEADER_VALUES[header]}")
        else:
            display = Fore.GREEN + value + Style.RESET_ALL
            results[header] = value
        print(f"{header}: {display}")
    results["Suggested Header Value"] = "; ".join(suggested_values)
    return results

def get_urls_from_user():
    print("Enter URLs one by one. Type 'done' when finished:")
    urls = []
    while True:
        url = input("> ").strip()
        if url.lower() == "done":
            break
        if url.startswith("http://") or url.startswith("https://"):
            urls.append(url)
        else:
            print("[!] URL must start with http:// or https://")
    return urls

def get_post_login_urls(login_url, max_pages=50):
    urls = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        page = browser.new_page()
        page.goto(login_url)
        input("[!] Please log in manually in the opened browser window. Press Enter here when done...")
        urls.append(page.url)
        # Simple crawl: get all links
        links = page.eval_on_selector_all("a", "elements => elements.map(e => e.href)")
        for link in links:
            if len(urls) >= max_pages:
                break
            if link.startswith("http"):
                urls.append(link)
        browser.close()
    return urls

def main():
    choice = input("Choose scan type (1=Pre-login, 2=Post-login): ").strip()
    all_results = []

    if choice == "1":
        urls = get_urls_from_user()
    elif choice == "2":
        login_url = input("Enter login page URL: ").strip()
        max_pages = input("Enter max pages to crawl: ").strip()
        max_pages = int(max_pages) if max_pages.isdigit() else 50
        urls = get_post_login_urls(login_url, max_pages)
    else:
        print("[!] Invalid choice. Exiting.")
        return

    if not urls:
        print("[!] No URLs to scan. Exiting.")
        return

    for url in urls:
        headers = fetch_headers(url)
        result = analyze_headers(url, headers)
        all_results.append(result)

    # Save to Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "Header Scan Results"
    columns = ["URL"] + HEADERS_TO_CHECK + ["Suggested Header Value"]
    ws.append(columns)

    for row in all_results:
        excel_row = []
        for col in columns:
            val = row.get(col, "")
            excel_row.append(val)
        ws.append(excel_row)
    
    # Color text in cells
    for row in ws.iter_rows(min_row=2):
        for cell in row[1:-1]:  # Skip URL and Suggested column
            if "MISSING" in str(cell.value):
                cell.font = Font(color="FF0000")  # Red
            elif "MISCONFIGURED" in str(cell.value):
                cell.font = Font(color="FFA500")  # Orange
            elif cell.value:
                cell.font = Font(color="008000")  # Green

    wb.save("headers_report_post_login.xlsx")
    print("\n[✔] All results saved to headers_report_post_login.xlsx")

if __name__ == "__main__":
    main()
