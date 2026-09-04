#!/usr/bin/env python3
"""
Subdomain Scanner Tool v2.0
دمج Subfinder + Sublist3r + Assetfinder + Amass + Httpx
مع دعم Wordlists متعددة
"""

import subprocess
import sys
import os
import re
import socket
import time
import random
import json
import argparse
import tempfile
import urllib.request
from typing import Optional, List, Set, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import shutil

# ===================== Config =====================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
]

MAX_WORKERS = 20
TIMEOUT = 6
RETRIES = 2

# Popular wordlists URLs
POPULAR_WORDLISTS = {
    'seclists': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
    'commonspeak': 'https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt',
    'all': 'https://raw.githubusercontent.com/chaoticag/chaos_dns_list/main/chaos_dns_list.txt',
    'best': 'https://raw.githubusercontent.com/Proximus-Research/Wordlists/main/subdomain.txt'
}

# ===================================================

def print_banner():
    """Print beautiful banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║     🚀 Subdomain Scanner Tool v2.0                       ║
    ║     By: [Your Name]                                     ║
    ║     Tools: Subfinder + Sublist3r + Assetfinder + Amass  ║
    ║     Wordlist Support: Multiple files & URLs             ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def download_wordlist(url: str) -> str:
    """Download wordlist from URL"""
    print(f"[+] Downloading wordlist from: {url}")
    try:
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        temp_path = temp_file.name
        
        # Download with progress
        urllib.request.urlretrieve(url, temp_path)
        
        # Check if download was successful
        if os.path.getsize(temp_path) > 0:
            print(f"[✓] Wordlist downloaded: {temp_path} ({os.path.getsize(temp_path)} bytes)")
            return temp_path
        else:
            os.unlink(temp_path)
            return None
    except Exception as e:
        print(f"[!] Failed to download wordlist: {e}")
        return None

def merge_wordlists(wordlist_paths: List[str]) -> str:
    """Merge multiple wordlists into one"""
    print(f"[+] Merging {len(wordlist_paths)} wordlists...")
    
    # Create temp merged file
    merged_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
    merged_path = merged_file.name
    
    all_words = set()
    
    for path in wordlist_paths:
        try:
            if path.startswith(('http://', 'https://')):
                # Download URL wordlist
                downloaded = download_wordlist(path)
                if downloaded:
                    path = downloaded
                else:
                    continue
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
                all_words.update(words)
                print(f"[+] Added {len(words)} words from: {os.path.basename(path)}")
        except Exception as e:
            print(f"[!] Error reading {path}: {e}")
    
    # Write merged wordlist
    with open(merged_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(all_words)))
    
    print(f"[✓] Total unique words: {len(all_words)}")
    print(f"[✓] Merged wordlist saved: {merged_path}")
    
    return merged_path

def create_default_wordlist() -> str:
    """Create default wordlist if needed"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_path = os.path.join(base_dir, "wordlist.txt")
    
    if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) > 0:
        return wordlist_path
    
    print("[+] Creating default wordlist...")
    # Common subdomain wordlist
    common_words = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal",
        "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
        "dns", "search", "ftp2", "test2", "xmpp", "mx1", "mail1", "webmail2",
        "mssql", "telnet", "remote", "ssh", "git", "crm", "erp", "jenkins", "jira",
        "confluence", "bitbucket", "gitlab", "sonar", "nexus", "artifactory"
    ]
    
    with open(wordlist_path, 'w') as f:
        f.write('\n'.join(common_words))
    
    print(f"[✓] Wordlist created at {wordlist_path} ({len(common_words)} words)")
    return wordlist_path

def check_and_install_tools():
    """Check if required tools are installed"""
    tools = {
        'subfinder': {
            'check': 'subfinder -version',
            'install': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
        },
        'httpx': {
            'check': 'httpx -version',
            'install': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'
        },
        'assetfinder': {
            'check': 'assetfinder --help',
            'install': 'go install github.com/tomnomnom/assetfinder@latest'
        },
        'amass': {
            'check': 'amass -version',
            'install': 'go install -v github.com/owasp-amass/amass/v4/...@master'
        }
    }
    
    missing_tools = []
    
    print("[+] Checking required tools...")
    for tool, commands in tools.items():
        try:
            subprocess.run(commands['check'].split(), capture_output=True, check=True)
            print(f"[✓] {tool} is installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"[!] {tool} is not installed")
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"\n[+] Installing missing tools: {', '.join(missing_tools)}")
        for tool in missing_tools:
            print(f"[+] Installing {tool}...")
            try:
                subprocess.run(tools[tool]['install'], shell=True, check=True)
                print(f"[✓] {tool} installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to install {tool}: {e}")
        print("[+] All tools installed successfully!")

def check_sublist3r():
    """Check and install Sublist3r"""
    try:
        import sublist3r
        print("[✓] Sublist3r is installed")
        return True
    except ImportError:
        print("[!] Sublist3r not installed, installing...")
        try:
            subprocess.run("pip install sublist3r", shell=True, check=True)
            print("[✓] Sublist3r installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("[!] Failed to install Sublist3r, skipping...")
            return False

def run_subfinder(domain: str) -> List[str]:
    """Run Subfinder"""
    print("[+] Running Subfinder...")
    subdomains = []
    try:
        cmd = ["subfinder", "-d", domain, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        print(f"[✓] Subfinder found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[!] Subfinder failed: {e}")
        return []

def run_sublist3r(domain: str) -> List[str]:
    """Run Sublist3r"""
    print("[+] Running Sublist3r...")
    subdomains = []
    try:
        import sublist3r
        subdomains = sublist3r.main(domain, 50, savefile=None, ports=None, 
                                  silent=True, verbose=False, enable_bruteforce=False, engines=None)
        print(f"[✓] Sublist3r found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[!] Sublist3r failed: {e}")
        return []

def run_assetfinder(domain: str) -> List[str]:
    """Run Assetfinder"""
    print("[+] Running Assetfinder...")
    subdomains = []
    try:
        cmd = ["assetfinder", "--subs-only", domain]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        print(f"[✓] Assetfinder found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[!] Assetfinder failed: {e}")
        return []

def run_amass(domain: str, wordlist_path: str = None) -> List[str]:
    """Run Amass with custom wordlist"""
    print("[+] Running Amass...")
    
    if not wordlist_path:
        wordlist_path = create_default_wordlist()
    
    if not os.path.isfile(wordlist_path) or os.path.getsize(wordlist_path) == 0:
        print("[!] Wordlist not found, running passive mode only")
        try:
            cmd = ["amass", "enum", "-passive", "-d", domain, "-nocolor"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            print(f"[✓] Amass (passive) found {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            print(f"[!] Amass failed: {e}")
            return []
    
    try:
        cmd = [
            "amass", "enum",
            "-brute", "-passive",
            "-d", domain,
            "-w", wordlist_path,
            "-timeout", "10",
            "-nocolor"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        print(f"[✓] Amass found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[!] Amass failed: {e}")
        return []

def extract_unique_domains(raw_list: List[str]) -> Set[str]:
    """Extract unique domains from raw results"""
    domains = set()
    
    # Patterns to filter
    ip_pattern = re.compile(r'\b\d{1,3}(\.\d{1,3}){3}\b')
    cidr_pattern = re.compile(r'/\d{1,2}')
    number_pattern = re.compile(r'^\s*\d+\s*$')
    
    for line in raw_list:
        line = line.strip()
        if not line:
            continue
            
        # Filter out IPs, CIDR, numbers
        if ip_pattern.search(line) or cidr_pattern.search(line) or number_pattern.match(line):
            continue
            
        # Handle Amass format with '-->'
        if '-->' in line:
            parts = line.split('-->')
            for part in parts:
                if '(FQDN)' in part:
                    domain = part.split('(FQDN)')[0].strip()
                    if domain:
                        domains.add(domain)
                else:
                    domain = part.strip()
                    if domain and '.' in domain:
                        domains.add(domain)
        else:
            domain = line.strip()
            if domain and '.' in domain and not domain.startswith(('http://', 'https://')):
                domains.add(domain)
    
    return domains

def run_httpx(domains: List[str]) -> List[Dict]:
    """Run httpx on domains"""
    print("[+] Running httpx for validation...")
    
    if not domains:
        return []
    
    # Write domains to temp file
    temp_file = "/tmp/httpx_input.txt"
    with open(temp_file, 'w') as f:
        f.write('\n'.join(domains))
    
    try:
        cmd = [
            "httpx",
            "-l", temp_file,
            "-status-code",
            "-title",
            "-content-length",
            "-tech-detect",
            "-follow-redirects",
            "-silent",
            "-json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        results = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    result_data = {
                        'url': data.get('url', ''),
                        'status_code': data.get('status_code', 0),
                        'title': data.get('title', ''),
                        'content_length': data.get('content_length', 0),
                        'tech': data.get('tech', []),
                        'webserver': data.get('webserver', ''),
                        'content_type': data.get('content_type', ''),
                    }
                    results.append(result_data)
                except json.JSONDecodeError:
                    if line.strip():
                        results.append({
                            'url': line.strip(),
                            'status_code': 0,
                            'title': '',
                            'content_length': 0,
                            'tech': [],
                            'webserver': '',
                            'content_type': '',
                        })
        
        print(f"[✓] httpx scanned {len(results)} domains")
        return results
        
    except Exception as e:
        print(f"[!] httpx failed: {e}")
        return []
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)

def save_subs_file(domains: Set[str], filename: str = "subs.txt"):
    """Save all subdomains to file"""
    with open(filename, 'w') as f:
        for domain in sorted(domains):
            f.write(domain + '\n')
    print(f"[✓] Saved {len(domains)} subdomains to {filename}")

def save_final_results(results: List[Dict], filename: str = "final.txt"):
    """Save final results with details"""
    with open(filename, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("FINAL SUBDOMAIN SCAN RESULTS\n")
        f.write("=" * 80 + "\n\n")
        
        results.sort(key=lambda x: x.get('status_code', 0), reverse=True)
        
        for result in results:
            url = result.get('url', 'N/A')
            status = result.get('status_code', 'N/A')
            title = result.get('title', 'No Title')[:50]
            content_length = result.get('content_length', 'N/A')
            tech = ', '.join(result.get('tech', []))[:50]
            webserver = result.get('webserver', 'N/A')
            
            f.write(f"{url}\n")
            f.write(f"  Status: {status} | Title: {title}\n")
            f.write(f"  Content-Length: {content_length} | Tech: {tech} | Server: {webserver}\n")
            f.write("-" * 80 + "\n")
        
        active = len([r for r in results if 200 <= r.get('status_code', 0) < 400])
        f.write(f"\nTotal domains scanned: {len(results)}\n")
        f.write(f"Active domains (200-399): {active}\n")
    
    print(f"[✓] Final results saved to {filename}")

def install_to_bin():
    """Install script to /usr/local/bin"""
    script_path = os.path.abspath(__file__)
    bin_path = "/usr/local/bin/subdomain-scanner"
    
    try:
        shutil.copy2(script_path, bin_path)
        os.chmod(bin_path, 0o755)
        print(f"[✓] Tool installed to {bin_path}")
        print("[+] You can now run: subdomain-scanner <domain> [options]")
    except PermissionError:
        print("[!] Permission denied. Try running with sudo:")
        print(f"    sudo cp {script_path} /usr/local/bin/subdomain-scanner")
        print("    sudo chmod +x /usr/local/bin/subdomain-scanner")

def main():
    """Main function"""
    print_banner()
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Advanced Subdomain Scanner with Multiple Wordlist Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with default wordlist
  subdomain-scanner example.com

  # Use custom wordlist file
  subdomain-scanner example.com -w /path/to/wordlist.txt

  # Use multiple wordlists
  subdomain-scanner example.com -w wordlist1.txt,wordlist2.txt,wordlist3.txt

  # Download and use wordlist from URL
  subdomain-scanner example.com -w https://example.com/wordlist.txt

  # Use popular SecLists wordlist
  subdomain-scanner example.com --use-seclists

  # Combine multiple sources
  subdomain-scanner example.com -w mylist.txt --use-seclists --use-commonspeak

  # Don't use any wordlist (passive only)
  subdomain-scanner example.com --no-wordlist
        """
    )
    
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('-w', '--wordlist', help='Wordlist file(s) - separate with commas for multiple files, supports URLs')
    parser.add_argument('--use-seclists', action='store_true', help='Download and use SecLists wordlist')
    parser.add_argument('--use-commonspeak', action='store_true', help='Download and use Commonspeak2 wordlist')
    parser.add_argument('--use-all', action='store_true', help='Download and use all popular wordlists')
    parser.add_argument('--no-wordlist', action='store_true', help='Don\'t use any wordlist (passive mode only)')
    parser.add_argument('--install', action='store_true', help='Install tool to /usr/local/bin')
    parser.add_argument('--max-workers', type=int, default=20, help='Maximum concurrent workers (default: 20)')
    parser.add_argument('--timeout', type=int, default=6, help='HTTP timeout in seconds (default: 6)')
    
    args = parser.parse_args()
    
    # Handle install flag
    if args.install:
        install_to_bin()
        sys.exit(0)
    
    domain = args.domain.strip()
    
    # Update global config
    global MAX_WORKERS, TIMEOUT
    MAX_WORKERS = args.max_workers
    TIMEOUT = args.timeout
    
    # Check and install tools
    check_and_install_tools()
    check_sublist3r()
    
    # Prepare wordlist
    wordlist_path = None
    
    if args.no_wordlist:
        print("[!] Wordlist disabled (passive mode only)")
    else:
        wordlist_sources = []
        
        # Add user provided wordlists
        if args.wordlist:
            wordlist_sources.extend(args.wordlist.split(','))
        
        # Add popular wordlists
        if args.use_seclists:
            wordlist_sources.append(POPULAR_WORDLISTS['seclists'])
        if args.use_commonspeak:
            wordlist_sources.append(POPULAR_WORDLISTS['commonspeak'])
        if args.use_all:
            wordlist_sources.extend(list(POPULAR_WORDLISTS.values()))
        
        # Process wordlists
        if wordlist_sources:
            if len(wordlist_sources) == 1 and not wordlist_sources[0].startswith(('http://', 'https://')):
                # Single local file
                if os.path.exists(wordlist_sources[0]):
                    wordlist_path = wordlist_sources[0]
                    print(f"[+] Using wordlist: {wordlist_path}")
                else:
                    print(f"[!] Wordlist not found: {wordlist_sources[0]}")
                    wordlist_path = create_default_wordlist()
            else:
                # Multiple sources or URL - merge them
                merged = merge_wordlists(wordlist_sources)
                if merged:
                    wordlist_path = merged
                else:
                    wordlist_path = create_default_wordlist()
        else:
            # Use default wordlist
            wordlist_path = create_default_wordlist()
    
    print(f"\n[+] Starting subdomain enumeration for: {domain}")
    print("=" * 60)
    
    # Phase 1: Collect subdomains
    print("\n[🔍] Phase 1: Collecting subdomains...")
    print("-" * 40)
    
    all_subdomains = set()
    
    # Run all tools
    subfinder_domains = run_subfinder(domain)
    all_subdomains.update(subfinder_domains)
    
    sublist3r_domains = run_sublist3r(domain)
    all_subdomains.update(sublist3r_domains)
    
    assetfinder_domains = run_assetfinder(domain)
    all_subdomains.update(assetfinder_domains)
    
    # Run Amass with the prepared wordlist
    amass_domains = run_amass(domain, wordlist_path)
    all_subdomains.update(amass_domains)
    
    # Extract unique domains
    unique_domains = extract_unique_domains(list(all_subdomains))
    
    print(f"\n[📊] Total unique subdomains collected: {len(unique_domains)}")
    
    # Phase 2: Save all subdomains
    print("\n[💾] Phase 2: Saving subdomains to file...")
    save_subs_file(unique_domains, "subs.txt")
    
    # Phase 3: Validate with httpx
    print("\n[🔬] Phase 3: Validating with httpx...")
    print("-" * 40)
    
    if unique_domains:
        httpx_results = run_httpx(list(unique_domains))
        active_domains = [r for r in httpx_results if 200 <= r.get('status_code', 0) < 400]
        
        print(f"\n[📊] Active domains (200-399): {len(active_domains)} out of {len(httpx_results)}")
        
        # Phase 4: Save final results
        print("\n[📝] Phase 4: Generating final output...")
        save_final_results(httpx_results, "final.txt")
    else:
        print("[!] No domains to scan with httpx")
        sys.exit(1)
    
    # Final summary
    print("\n" + "=" * 60)
    print("[✅] SCAN COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print(f"📁 All subdomains: subs.txt ({len(unique_domains)} domains)")
    print(f"📁 Active domains: final.txt ({len(active_domains)} active)")
    
    # Show wordlist info
    if wordlist_path and not args.no_wordlist:
        print(f"📄 Wordlist used: {wordlist_path}")

if __name__ == "__main__":
    main()
