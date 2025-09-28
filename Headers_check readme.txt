HTTP Security Headers Scanner

A Python script to automatically check HTTP security headers for pre-login and post-login pages.
It identifies missing or misconfigured headers and suggests correct values to improve web application security.

✨ Features
🌐 Crawl websites and analyze both pre-login and post-login pages
🔍 Detect missing or misconfigured HTTP security headers
🛡️ Suggest correct values for misconfigured or missing headers
📊 Export results into an Excel file (headers_report.xlsx) with color-coded text
🖥️ CLI interface with user-friendly prompts

📦 Requirements
Python 3.8+
pip (comes with Python)
requests (for HTTP requests)
openpyxl (for Excel export)
colorama (for colored CLI output)
playwright (for post-login crawling, optional if you want automated login crawling)
Chromium (installed via Playwright if using post-login crawling)

⚡ Installation
pip install requests openpyxl colorama playwright
playwright install
playwright install chromium

▶️ Usage
Pre-login header scan
python headers_scanner.py


Choose Pre-login when prompted
Enter URLs one by one
Type done when finished
Check results in headers_report.xlsx
Post-login header scan
python headers_scanner.py


Choose Post-login when prompted
Enter login page URL
Open browser, log in manually, then press Enter
Script will crawl post-login links and check headers
Results are saved in headers_report.xlsx

🛠️ How it works
The script prompts the user for the scan type: Pre-login or Post-login.
For pre-login, it fetches headers for given URLs.
For post-login, it uses a browser to navigate the logged-in session and capture internal links.
Checks the following HTTP headers:
Strict-Transport-Security
Content-Security-Policy
X-Content-Type-Options
Access-Control-Allow-Origin
X-Frame-Options
X-XSS-Protection
Detects missing or misconfigured headers based on simple rules.
Suggests correct values for headers in the last column of the Excel file.
Color-codes header values in Excel:
Green = OK
Yellow = Misconfigured
Red = Missing

✅ Output
headers_report.xlsx
Columns: URL, each HTTP header, Suggested Correct Values
Misconfigured/missing headers are highlighted in color

