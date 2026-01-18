#!/usr/bin/env python3
"""
API RECON TOOL v3.0 - Interactive & Advanced API Reconnaissance Framework
Author: Security Research

Features:
- Interactive Menu System
- Multi-threaded scanning (500+ endpoints)
- Advanced 403/401 Bypass (Headers, URL mutation)
- OpenAPI/Swagger & GraphQL auto-detection
- Sensitive Info Extractor (API Keys, Emails, JWTs)
- Automatic dumping of all findings
"""

import requests
import json
import sys
import os
import re
import argparse
import time
import random
import string
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= COLORS =================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ================= CONFIG =================
DEFAULT_THREADS = 25
DEFAULT_TIMEOUT = 8
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
]

# ================= WORDLISTS =================
API_ENDPOINTS = [
    # Top Critical
    "/api", "/v1", "/api/v1", "/graphql", "/swagger.json", "/openapi.json", "/.env",
    "/actuator", "/health", "/admin", "/login", "/config.json", "/.git/config",
    
    # Swagger / Docs
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/api-docs", "/v2/api-docs",
    "/v3/api-docs", "/api/swagger.json", "/api/docs", "/doc", "/documentation",
    "/redoc", "/rapidoc", "/explorer",
    
    # GraphQL
    "/graphiql", "/playground", "/graphql/console", "/v1/graphql", "/api/graphql",
    
    # Cloud / Ops
    "/metrics", "/prometheus", "/dashboard", "/trace", "/info", "/version",
    "/phpinfo.php", "/server-status", "/aws/credentials", "/s3",
    
    # Admin / Auth
    "/auth", "/oauth/token", "/users", "/user", "/me", "/account",
    "/register", "/signup", "/password-recovery", "/forgot-password",
    "/console", "/manage", "/portal", "/backoffice", "/cms",
    
    # Data
    "/products", "/items", "/orders", "/customers", "/clients",
    "/files", "/uploads", "/images", "/assets", "/export", "/import",
    "/debug", "/test", "/dev", "/staging", "/internal", "/private"
]

# Advanced Bypass Headers
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Referer": "https://{target_host}/admin"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
]

# URL Mutation for Bypass (suffixes)
URL_MUTATIONS = [
    "/.", "//", ";/", "..;/", "%20", "%09", ".json"
]

# Info Extractors (Regex)
PATTERNS = {
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "IP Address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    "JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "API Key": r"(api_key|apikey|secret|token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9-_]{16,})",
    "Private Key": r"-----BEGIN [A-Z]+ PRIVATE KEY-----",
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Internal Path": r"(\/var\/www|\/home\/|\/etc\/|\/opt\/|C:\\Windows|C:\\Users)"
}

# ================= CLASS =================
class APIScanner:
    def __init__(self, target, output_dir="api_dumps"):
        self.target = self._clean_url(target)
        self.host = urlparse(self.target).netloc
        self.output_dir = output_dir
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        self.results = {
            "target": self.target,
            "endpoints": [],
            "vulnerabilities": [],
            "leaks": [],
            "technologies": []
        }
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def _clean_url(self, url):
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url.rstrip('/')

    def _log(self, msg, type="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        if type == "SUCCESS":
            print(f"{Colors.GREEN}[+] {msg}{Colors.END}")
        elif type == "ALERT":
            print(f"{Colors.RED}[!] {msg}{Colors.END}")
        elif type == "WARN":
            print(f"{Colors.YELLOW}[~] {msg}{Colors.END}")
        else:
            print(f"{Colors.BLUE}[*] {msg}{Colors.END}")

    def scan_endpoint(self, endpoint):
        full_url = f"{self.target}{endpoint}"
        try:
            resp = self.session.get(full_url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=False)
            
            # Analyze Response
            if resp.status_code in [200, 401, 403, 500]:
                content_len = len(resp.content)
                status = resp.status_code
                
                # Filter noise
                if status == 404: return None
                
                redirect = resp.headers.get('Location', '')
                
                # Print result
                color = Colors.GREEN if status == 200 else Colors.YELLOW if status in [401, 403] else Colors.RED
                print(f"{color}[{status}] {endpoint:<30} Size: {content_len:<8} {redirect}{Colors.END}")
                
                # Advanced Analysis
                self._analyze_response(resp, full_url)
                
                # If 403/401, start Bypass Routine
                if status in [403, 401]:
                    self._attempt_bypass(endpoint)
                    
                return {"url": full_url, "status": status, "size": content_len}
                
        except Exception:
            return None

    def _analyze_response(self, resp, url):
        # 1. Tech Stack
        headers = resp.headers
        server = headers.get("Server") or headers.get("X-Powered-By")
        if server and server not in self.results["technologies"]:
            self.results["technologies"].append(server)
            self._log(f"Tech Detected: {server}", "WARN")

        # 2. Swagger/OpenAPI Check
        if "swagger" in resp.text.lower() or "openapi" in resp.text.lower():
            self._log(f"Swagger/OpenAPI detected at {url}", "SUCCESS")
            self._dump_file("swagger_spec.json", resp.text)
            self.results["vulnerabilities"].append({"type": "Info Disclosure", "detail": "Swagger Docs", "url": url})

        # 3. GraphQL Check
        if "graphql" in url or "__schema" in resp.text:
            self._log(f"GraphQL Endpoint detected at {url}", "SUCCESS")
            self._check_graphql_introspection(url)

        # 4. Sensitive Data Extraction
        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, resp.text)
            if matches:
                unique_matches = list(set(matches))[:5] # Limit display
                self._log(f"Found {name}: {unique_matches}", "ALERT")
                self.results["leaks"].append({"type": name, "matches": unique_matches, "url": url})

    def _attempt_bypass(self, endpoint):
        """ Try to bypass 403/401 using headers and mutations """
        full_url = f"{self.target}{endpoint}"
        
        # Method 1: Headers
        for headers in BYPASS_HEADERS:
            # Inject target host if needed
            h = headers.copy()
            if "Referer" in h: h["Referer"] = h["Referer"].format(target_host=self.host)
            
            try:
                resp = self.session.get(full_url, headers=h, timeout=5, verify=False)
                if resp.status_code == 200:
                    self._log(f"BYPASS SUCCESS! {endpoint} with headers: {h}", "SUCCESS")
                    self.results["vulnerabilities"].append({"type": "Auth Bypass", "headers": h, "url": full_url})
                    return
            except: pass

        # Method 2: URL Mutations
        for mutation in URL_MUTATIONS:
            if endpoint.endswith('/'): base = endpoint[:-1]
            else: base = endpoint
            
            mutated_url = f"{self.target}{base}{mutation}"
            try:
                resp = self.session.get(mutated_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    self._log(f"BYPASS SUCCESS! URL Mutation: {mutated_url}", "SUCCESS")
                    self.results["vulnerabilities"].append({"type": "Auth Bypass", "mutation": mutation, "url": mutated_url})
                    return
            except: pass

    def _check_graphql_introspection(self, url):
        query = {"query": "{__schema{types{name}}}"}
        try:
            resp = self.session.post(url, json=query, timeout=5, verify=False)
            if resp.status_code == 200 and "__schema" in resp.text:
                self._log(f"GraphQL Introspection ENABLED at {url}", "SUCCESS")
                self._dump_file("graphql_schema.json", resp.text)
        except: pass

    def _dump_file(self, filename, content):
        path = os.path.join(self.output_dir, f"{self.host}_{filename}")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        self._log(f"Dumped content to {path}", "INFO")

    def start(self):
        print(f"\n{Colors.BOLD}Starting Scan on: {self.target}{Colors.END}")
        print(f"Threads: {DEFAULT_THREADS} | Timeout: {DEFAULT_TIMEOUT}s")
        print("-" * 50)
        
        # 1. Base Scan
        with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
            futures = [executor.submit(self.scan_endpoint, ep) for ep in API_ENDPOINTS]
            for future in as_completed(futures):
                res = future.result()
                if res and res['status'] == 200:
                    self.results["endpoints"].append(res)

        # 2. Save Final Report
        report_path = os.path.join(self.output_dir, f"{self.host}_full_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=4)
        
        print("-" * 50)
        self._log(f"Scan Completed. Full report: {report_path}", "SUCCESS")

# ================= INTERACTIVE MENU =================
def interactive_mode():
    while True:
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== API RECON FRAMEWORK V3 ==={Colors.END}")
        print("1. Scan Single Target")
        print("2. Mass Scan (File list)")
        print("3. Add Custom Endpoint to Wordlist")
        print("4. View Dumps Folder")
        print("5. Exit")
        
        choice = input(f"\n{Colors.YELLOW}Select an option > {Colors.END}")
        
        if choice == "1":
            target = input(f"{Colors.BLUE}Enter Target URL (e.g. api.target.com): {Colors.END}")
            if target:
                scanner = APIScanner(target)
                scanner.start()
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            filepath = input(f"{Colors.BLUE}Enter path to targets file: {Colors.END}")
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                
                print(f"{Colors.GREEN}[+] Loaded {len(targets)} targets.{Colors.END}")
                for t in targets:
                    print(f"\n{Colors.MAGENTA}>>> Scanning: {t}{Colors.END}")
                    scanner = APIScanner(t)
                    scanner.start()
            else:
                print(f"{Colors.RED}[!] File not found.{Colors.END}")
            input("\nPress Enter to continue...")
            
        elif choice == "3":
            new_ep = input(f"{Colors.BLUE}Enter endpoint (e.g. /private/admin): {Colors.END}")
            if new_ep:
                API_ENDPOINTS.append(new_ep)
                print(f"{Colors.GREEN}[+] Added {new_ep} to current session wordlist.{Colors.END}")
        
        elif choice == "4":
            print(f"\n{Colors.YELLOW}Listing 'api_dumps/' directory:{Colors.END}")
            if os.path.exists("api_dumps"):
                os.system("ls -l api_dumps")
            else:
                print("No dumps yet.")
            input("\nPress Enter to continue...")
            
        elif choice == "5":
            print("Exiting...")
            sys.exit()
        
        else:
            print("Invalid choice.")

# ================= MAIN =================
if __name__ == "__main__":
    banner = f"""
    {Colors.RED}
       db    88""Yb 88        88""Yb 888888  dP""b8  dP"Yb  88b 88 
      dPYb   88__dP 88  ____  88__dP 88__   dP   `" dP   Yb 88Yb88 
     dP__Yb  88'''  88  """"  88"Yb  88""   Yb      Yb   dP 88 Y88 
    dP""""Yb 88     88        88  Yb 888888  YboodP  YbodP  88  Y8 {Colors.END}
    {Colors.CYAN} Interactive API Recontool & Exploiter {Colors.END}
    """
    print(banner)
    
    # Check if arguments provided
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Quick scan a single target (Non-interactive)")
    args = parser.parse_args()
    
    if args.target:
        scanner = APIScanner(args.target)
        scanner.start()
    else:
        interactive_mode()
