import subprocess
import sys
import os
import re
import socket
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import aiohttp
from typing import Optional, List, Tuple
from aiohttp import ClientSession, ClientTimeout

# ===================== Config =====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]
MAX_WORKERS = 20
RETRIES = 2
TIMEOUT = 6
# ===================================================

# ------------------- Amass Section -------------------
def run_amass(domain: str) -> List[str]:
    """
    Run Amass in the background, return list of found subdomains
    without printing anything or saving to file.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist = os.path.join(base_dir, "wordlist.txt")

    if not os.path.isfile(wordlist) or os.path.getsize(wordlist) == 0:
        return []

    output_subdomains = []

    try:
        command = [
            "amass", "enum",
            "-brute", "-passive",
            "-d", domain,
            "-w", wordlist,
            "-timeout", "10",
            "-nocolor"
        ]

        # تشغيل الأمر
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # جمع كل النتائج في القائمة بدل الطباعة
        for line in process.stdout:
            line = line.strip()
            if line:
                output_subdomains.append(line)

        process.wait()
        return output_subdomains

    except FileNotFoundError:
        return []
    except Exception:
        return []

# ------------------- Subdomain Checker Section -------------------
def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        "Via": "1.1 proxy"
    }

def dns_check(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def check_subdomain(subdomain):
    protocols = ["https://", "http://"]
    if subdomain.startswith(("http://", "https://")):
        domain_only = subdomain.split("//", 1)[1].split("/")[0]
        protocols = [""]
    else:
        domain_only = subdomain

    if not dns_check(domain_only):
        return False

    for proto in protocols:
        url = proto + subdomain if proto else subdomain
        for _ in range(RETRIES):
            try:
                resp = requests.get(url, headers=get_headers(), timeout=TIMEOUT, allow_redirects=True)
                if resp.status_code == 429:
                    time.sleep(random.uniform(1, 2))
                    continue
                if 200 <= resp.status_code < 400:
                    return True
            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.RequestException):
                pass
            time.sleep(1)
    return False

def extract_unique_domains_from_list(raw_list: List[str]) -> List[str]:
    domains = []
    ip_or_cidr_pattern = re.compile(
        r"(\b\d{1,3}(\.\d{1,3}){3}\b)|"
        r"([0-9a-fA-F:]+:+)+[0-9a-fA-F]+|"
        r"(\/\d{1,2})"
    )
    num_only_pattern = re.compile(r"^\s*\d+\s*$")

    for line in raw_list:
        if "(Netblock)" in line or "(ASN)" in line:
            continue
        if ip_or_cidr_pattern.search(line) or num_only_pattern.match(line):
            continue

        parts = line.strip().split('-->')
        if len(parts) >= 2:
            first = parts[0].split('(FQDN)')[0].strip()
            second = parts[-1].split('(FQDN)')[0].strip()
            domains.extend([first, second])
        else:
            domains.append(line.strip())

    return list(dict.fromkeys(domains))

def normalize_url(url: str) -> Optional[str]:
    url = url.strip()
    if not url or url.startswith('#'):
        return None
    if not re.match(r'[](http://|https://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url):
        return None
    if not url.startswith(('http://', 'https://')):
        url =  url
    return url

async def get_redirect_chain(url: str, session: ClientSession, max_retries: int = 3) -> Tuple[List[str], bool]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    for attempt in range(max_retries):
        try:
            async with session.get(url, headers=headers, allow_redirects=True, timeout=ClientTimeout(total=15)) as resp:
                history_urls = [str(h.url) for h in resp.history]
                final_url = str(resp.url)
                chain = [url] + history_urls[1:] + [final_url] if history_urls else [url]
                is_redirect = len(history_urls) > 0
                return chain, is_redirect
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt == max_retries - 1:
                return [url], False
            await asyncio.sleep(1)
    return [url], False

async def process_urls(raw_urls: List[str], output_file: str):
    all_urls = set(raw_urls)
    async with aiohttp.ClientSession() as session:
        tasks = []
        seen_urls = set()
        for raw in raw_urls:
            nu = normalize_url(raw)
            if nu and nu not in seen_urls:
                seen_urls.add(nu)
                tasks.append(get_redirect_chain(nu, session))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, tuple):
                chain, is_redirect = result
                if is_redirect:
                    for u in chain[1:]:
                        all_urls.add(u)

    with open(output_file, 'w', encoding='utf-8') as out:
        for url in raw_urls:
            out.write(url + "\n")
        new_urls = sorted(all_urls - set(raw_urls))
        for url in new_urls:
            out.write(url + "\n")

# ------------------- Main Combined Script -------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {os.path.basename(__file__)} <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Step 1: Run Amass in background, gather results
    raw_amass_results = run_amass(domain)

    if not raw_amass_results:
        print("[!] No results from Amass.")
        sys.exit(1)

    # Step 2: Extract unique subdomains
    subdomains = extract_unique_domains_from_list(raw_amass_results)

    # Step 3: Check which subdomains are working
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(future_to_domain):
            sub = future_to_domain[future]
            try:
                if future.result():
                    working.append(sub)
            except Exception:
                pass

    # Step 4: Process redirects and save final results
    output_file = "OutPut.txt"
    asyncio.run(process_urls(working, output_file))
    print(f"[+] Done! Results saved in {output_file}")

if __name__ == "__main__":
    main()
