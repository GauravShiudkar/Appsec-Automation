# Appsec-Automation
This scripts will help you to reduce the time of manually checking for libraries and versions 

1. Requirements:
Python: version 3.8 or newer
pip (comes with Python)
Playwright (for headless browser automation)
Chromium browser binaries (installed via Playwright)
requests (for querying npm + OSV databases)

2.Command in cmd:
pip install playwright requests
playwright install
playwright install chromium
python crawl_detect_libs_deeper.py (Tp crawl all libraries from website)
python vulnlibs_detect.py (TO find out vulnerable and outdated libraries)

3.It work like:
You will be prompted for:
Starting URL (e.g. https://example.com)
Max pages to crawl (e.g. 20)

4.Result
Crawl internal pages
Detect libraries (via filenames, content, runtime checks)
Save results into findings.csv
