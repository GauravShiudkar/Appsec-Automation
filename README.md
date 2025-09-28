# 🚀 Vulnerable Library Detector

A set of Python scripts to **automatically detect libraries and their versions** from websites, saving time compared to manual checks.  
It also identifies **outdated or vulnerable dependencies** using OSV and npm databases.

---

## ✨ Features
- 🌐 Crawl websites and analyze internal pages  
- 🔍 Detect libraries via filenames, content, and runtime checks  
- 🛡️ Identify outdated and vulnerable dependencies  
- 📊 Export results into `findings.csv`  

---

## 📦 Requirements
- Python **3.8+**  
- pip (comes with Python)  
- [Playwright](https://playwright.dev/python/) (for headless browser automation)  
- Chromium (installed via Playwright)  
- requests (for querying npm + OSV databases)  

---

## ⚡ Installation
```bash
pip install playwright requests
playwright install
playwright install chromium
```

## ▶️ Usage
Crawl all libraries from a website
```bash
python crawl_detect_libs_deeper.py
```

Detect vulnerable and outdated libraries
```bash
python vulnlibs_detect.py
```

---

## 🛠️ How it works

When you run the script, you’ll be prompted for:
Starting URL (e.g. https://example.com)
Max pages to crawl (e.g. 20)
Then the script will:
Crawl internal pages
Detect libraries (via filenames, content, and runtime checks)
Save results into findings.csv

---

# 🚀 HTTP Security Headers Scanner

A Python script to automatically check HTTP security headers for pre-login and post-login pages.
It identifies missing or misconfigured headers and suggests correct values to improve web application security.

## ✨ Features

🌐 Crawl websites and analyze both pre-login and post-login pages

🔍 Detect missing or misconfigured HTTP security headers

🛡️ Suggest correct values for misconfigured or missing headers

📊 Export results into an Excel file (headers_report.xlsx) with color-coded text

🖥️ CLI interface with user-friendly prompts

## 📦 Requirements

- Python 3.8+
- pip (comes with Python)
- requests (for HTTP requests)
- openpyxl (for Excel export)
- colorama (for colored CLI output)
- playwright (optional for post-login crawling)
- Chromium (installed via Playwright if using post-login crawling)

## ⚡ Installation
```bash
pip install requests openpyxl colorama playwright
playwright install
playwright install chromium
```

## ▶️ Usage
Pre-login header scan
```bash
python headers_scanner.py
```

- Choose Pre-login when prompted
- Enter URLs one by one
- Type done when finished
- Check results in headers_report.xlsx

Post-login header scan
```bash
python headers_scanner.py
```

- Choose Post-login when prompted
- Enter login page URL
- Open browser, log in manually, then press Enter
- Script will crawl post-login links and check headers
- Results are saved in headers_report.xlsx

## 🛠️ How it works

- Script prompts for scan type: Pre-login or Post-login
- Pre-login: fetches headers for given URLs
- Post-login: navigates the logged-in session and captures internal links
- Checks the following HTTP headers:
- **Strict-Transport-Security**
- **Content-Security-Policy**
- **X-Content-Type-Options**
- **Access-Control-Allow-Origin**
- **X-Frame-Options**
- **X-XSS-Protection**

- Detects missing or misconfigured headers
- Suggests correct values in the last column of the Excel file
- Color-codes header values in Excel:
- Green = OK
- Yellow = Misconfigured
- Red = Missing

## ✅ Output
- headers_report.xlsx
- Columns: URL, each HTTP header, Suggested Correct Values
- Misconfigured/missing headers are highlighted in color
