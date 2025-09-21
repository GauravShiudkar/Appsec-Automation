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

## ▶️ Usage
Crawl all libraries from a website
python crawl_detect_libs_deeper.py

Detect vulnerable and outdated libraries
python vulnlibs_detect.py

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
