
import requests
import argparse
import sys
import html
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class C:
    G, R, Y, B, E = '\033[92m', '\033[91m', '\033[93m', '\033[94m', '\033[0m'

class Scanner:
    def __init__(self, url):
        self.session = requests.Session()
        self.target = url
        self.domain = urlparse(url).netloc
        self.visited = []
        self.findings = []
        
        
        self.headers = {'User-Agent': 'Mozilla/5.0 (Security-Audit/1.0)'}
        self.xss_payloads = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"]
        self.sql_payloads = ["'", "' OR '1'='1", '" OR "1"="1']
        self.sql_errors = ["sql syntax", "mysql", "unclosed quotation", "microsoft ole db"]
        self.files = ["admin/", "login/", ".env", "config.php", ".git/", "robots.txt"]
        
        
        self.mitigations = {
            "XSS": "Sanitize user input on server-side. Use Content-Security-Policy (CSP).",
            "SQL Injection": "Use Prepared Statements (Parameterized Queries). Never concatenate input.",
            "CSRF": "Implement Anti-CSRF tokens in all POST/PUT/DELETE forms.",
            "Missing Headers": "Configure web server to send X-Frame-Options and HSTS headers.",
            "Sensitive File": "Restrict access via permissions (chmod/htaccess) or remove from public folder."
        }

    def log(self, msg, type="info"):
        if type == "plus": print(f"{C.G}[+] {msg}{C.E}")
        elif type == "warn": print(f"{C.Y}[!] {msg}{C.E}")
        elif type == "vuln": print(f"{C.R}[!!!] {msg}{C.E}")
        else: print(f"{C.B}[*] {msg}{C.E}")

    def add_finding(self, type, url, payload):
        self.findings.append({
            "type": type, "url": url, "payload": payload,
            "fix": self.mitigations.get(type, "Check OWASP guidelines.")
        })

    def report(self):
        fname = f"scan_report_{self.domain}.html"
        self.log(f"Generating report: {fname}...", "info")
        
        rows = ""
        for f in self.findings:
            rows += f"""<tr>
                <td style="color:red; font-weight:bold;">{html.escape(f['type'])}</td>
                <td>{html.escape(f['url'])}</td>
                <td><code>{html.escape(f['payload'])}</code></td>
                <td style="color:green; font-style:italic;">{html.escape(f['fix'])}</td>
            </tr>"""

        template = f"""
        <html><head><title>Scan Report - {self.target}</title>
        <style>body{{font-family:monospace;padding:20px;background:#1a1a1a;color:#ddd}}
        table{{width:100%;border-collapse:collapse;background:#252525;margin-top:20px}}
        th,td{{border:1px solid #444;padding:10px;text-align:left;vertical-align:top}}
        th{{background:#333;color:#0f0}} a{{color:#4da6ff}} 
        .summary{{border:1px solid #444;padding:15px;background:#202020}}</style></head>
        <body>
        <div class="summary"><h2>TARGET: {self.target}</h2>
        <h3>ISSUES FOUND: {len(self.findings)}</h3>
        <small>Generated: {datetime.now()}</small></div>
        <table><tr><th>VULNERABILITY</th><th>ENDPOINT</th><th>PAYLOAD / DETAILS</th><th>MITIGATION</th></tr>{rows}</table>
        </body></html>"""
        
        with open(fname, "w") as f: f.write(template)
        self.log("Report saved.", "plus")

    def request(self, url, method="GET", data=None):
        try:
            if method == "POST": 
                return self.session.post(url, data=data, headers=self.headers, timeout=5)
            return self.session.get(url, params=data, headers=self.headers, timeout=5)
        except: return None

    def crawl(self, url):
        resp = self.request(url)
        if not resp: return
        soup = BeautifulSoup(resp.content, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a['href']).split("#")[0]
            if self.domain in link and link not in self.visited:
                self.visited.append(link)
                print(f"\r{C.B}[*] Crawling: {len(self.visited)} links found...{C.E}", end="")
                if len(self.visited) < 50: self.crawl(link)

    def audit_headers(self):
        self.log("Checking security headers...", "info")
        headers = self.request(self.target).headers
        missing = [h for h in ["X-Frame-Options", "Content-Security-Policy"] if h not in headers]
        if missing: 
            self.add_finding("Missing Headers", self.target, ", ".join(missing))
            self.log(f"Missing headers: {', '.join(missing)}", "warn")

    def fuzz_files(self):
        self.log("Fuzzing sensitive files...", "info")
        for path in self.files:
            target = urljoin(self.target, path)
            res = self.request(target)
            if res and res.status_code == 200:
                self.log(f"Exposed: {target}", "vuln")
                self.add_finding("Sensitive File", target, "HTTP 200 OK")

    def audit_forms(self):
        print() 
        self.log(f"Auditing forms on {len(self.visited)} URLs...", "info")
        for link in self.visited:
            res = self.request(link)
            if not res: continue
            soup = BeautifulSoup(res.content, "html.parser")
            
            for form in soup.find_all("form"):
                action = urljoin(link, form.get("action"))
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                
                
                if method == "post":
                    if not any(x in str(inputs).lower() for x in ["csrf", "token"]):
                        self.log(f"Potential CSRF: {link}", "warn")
                        self.add_finding("CSRF", link, "No anti-CSRF token found")

                
                for payload in self.xss_payloads + self.sql_payloads:
                    data = {}
                    for inp in inputs:
                        if inp.get("type") in ["text", "search", "url"]:
                            data[inp.get("name")] = payload
                        else:
                            data[inp.get("name")] = inp.get("value")
                    
                    resp = self.request(action, method.upper(), data)
                    if not resp: continue
                    
                    if payload in self.xss_payloads and payload in resp.text:
                        self.log(f"XSS Found: {link}", "vuln")
                        self.add_finding("XSS", link, payload)
                        break
                    
                    if payload in self.sql_payloads and any(e in resp.text.lower() for e in self.sql_errors):
                        self.log(f"SQLi Found: {link}", "vuln")
                        self.add_finding("SQL Injection", link, payload)
                        break

    def start(self):
        print(rf"""{C.G}
   _  _  ____  ___    ___   ___   __   __ _  __  
  ( \/ )(  __)/ __)  / __) / __) / _\ (  ( \(  ) 
   )  /  ) _)( (__   \__ \( (__ /    \/    / )(__
  (__/  (____)\___)  (___/ \___)\_/\_/\_)__)(____) v2.0{C.E}
        """)
        try:
            self.audit_headers()
            self.fuzz_files()
            self.crawl(self.target)
            self.audit_forms()
            self.report()
        except KeyboardInterrupt:
            print(f"\n{C.R}Aborted.{C.E}")
            self.report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    args = parser.parse_args()
    Scanner(args.url).start()