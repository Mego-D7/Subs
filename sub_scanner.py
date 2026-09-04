#!/usr/bin/env python3
"""
Subdomain Scanner Tool v3.0 - Professional Edition
Advanced Multi-Threaded Subdomain Discovery with DNS + HTTP Validation
Author: SWIVAN017
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
import asyncio
import aiohttp
import dns.resolver
from typing import Optional, List, Set, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import requests
import shutil
import threading
from queue import Queue
from dataclasses import dataclass
import signal
import hashlib

# Try to import colorama, fallback if not available
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback if colorama not installed
    class Fore:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
    class Style:
        BRIGHT = '\033[1m'
        DIM = '\033[2m'
    def init(autoreset=True):
        pass

# ===================== Configuration =====================
@dataclass
class ScanConfig:
    """Configuration for the scanner"""
    max_workers: int = 50
    dns_timeout: int = 5
    http_timeout: int = 8
    retries: int = 2
    rate_limit: int = 100
    dns_retries: int = 3
    use_async: bool = True
    verbose: bool = False
    output_dir: str = "."
    show_progress: bool = True

# Enhanced User Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

# DNS Resolvers (multiple for reliability)
DNS_RESOLVERS = [
    '1.1.1.1',      # Cloudflare
    '8.8.8.8',      # Google
    '9.9.9.9',      # Quad9
    '208.67.222.222', # OpenDNS
    '1.0.0.1',      # Cloudflare Secondary
    '8.8.4.4',      # Google Secondary
]

# Popular Wordlists URLs
POPULAR_WORDLISTS = {
    'seclists': 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
    'commonspeak': 'https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt',
    'chaos': 'https://raw.githubusercontent.com/chaoticag/chaos_dns_list/main/chaos_dns_list.txt',
    'best': 'https://raw.githubusercontent.com/Proximus-Research/Wordlists/main/subdomain.txt'
}

# ==========================================================

class DNSChecker:
    """Advanced DNS checker with multiple resolvers and async support"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.resolver_cache = {}
        self.stats = {'total': 0, 'valid': 0, 'invalid': 0}
        
    async def check_async(self, domain: str) -> bool:
        """Async DNS check with caching and multiple resolvers"""
        domain = domain.lower().strip()
        
        # Check cache first
        with self.cache_lock:
            if domain in self.cache:
                self.stats['total'] += 1
                return self.cache[domain]
        
        self.stats['total'] += 1
        
        # Try multiple resolvers
        for resolver_ip in DNS_RESOLVERS:
            try:
                # Create resolver with specific nameserver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                resolver.timeout = self.config.dns_timeout
                resolver.lifetime = self.config.dns_timeout
                
                # Try A record first
                try:
                    answers = resolver.resolve(domain, 'A')
                    if answers and len(answers) > 0:
                        with self.cache_lock:
                            self.cache[domain] = True
                            self.stats['valid'] += 1
                        return True
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    pass
                
                # Try AAAA record
                try:
                    answers = resolver.resolve(domain, 'AAAA')
                    if answers and len(answers) > 0:
                        with self.cache_lock:
                            self.cache[domain] = True
                            self.stats['valid'] += 1
                        return True
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    pass
                    
            except Exception as e:
                if self.config.verbose:
                    print(f"{Fore.YELLOW}[DNS] Resolver {resolver_ip} failed for {domain}: {e}")
                continue
        
        # All resolvers failed
        with self.cache_lock:
            self.cache[domain] = False
            self.stats['invalid'] += 1
        return False
    
    def check_sync(self, domain: str) -> bool:
        """Sync DNS check (fallback)"""
        domain = domain.lower().strip()
        
        with self.cache_lock:
            if domain in self.cache:
                return self.cache[domain]
        
        try:
            socket.gethostbyname(domain)
            with self.cache_lock:
                self.cache[domain] = True
                self.stats['valid'] += 1
            return True
        except socket.gaierror:
            with self.cache_lock:
                self.cache[domain] = False
                self.stats['invalid'] += 1
            return False
    
    def get_stats(self) -> Dict:
        """Get DNS statistics"""
        return self.stats

class SubdomainScanner:
    """Main scanner class with advanced features"""
    
    def __init__(self, domain: str, config: ScanConfig):
        self.domain = domain.lower().strip()
        self.config = config
        self.dns_checker = DNSChecker(config)
        self.results = {
            'all_subdomains': set(),
            'valid_dns': set(),
            'http_results': [],
            'stats': {
                'tools': {},
                'dns': {},
                'http': {}
            }
        }
        self.start_time = time.time()
        
    def print_progress(self, current: int, total: int, message: str = ""):
        """Print progress bar"""
        if not self.config.show_progress:
            return
            
        if total > 0:
            percent = (current / total) * 100 if total > 0 else 0
            bar_length = 40
            filled = int(bar_length * current / total)
            bar = '█' * filled + '░' * (bar_length - filled)
            sys.stdout.write(f'\r[{bar}] {percent:5.1f}% - {message}')
            sys.stdout.flush()
    
    def _run_subfinder(self) -> List[str]:
        """Run Subfinder with advanced options"""
        print(f"{Fore.CYAN}[+] Running Subfinder...")
        subdomains = []
        try:
            cmd = ["subfinder", "-d", self.domain, "-all", "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            subdomains = [line.strip().lower() for line in result.stdout.split('\n') if line.strip()]
            print(f"{Fore.GREEN}✓ Subfinder: {len(subdomains)} subdomains")
            self.results['stats']['tools']['subfinder'] = len(subdomains)
            return subdomains
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}⚠ Subfinder timed out")
            return []
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}✗ Subfinder error: {e}")
            return []
    
    def _run_sublist3r(self) -> List[str]:
        """Run Sublist3r"""
        print(f"{Fore.CYAN}[+] Running Sublist3r...")
        subdomains = []
        try:
            import sublist3r
            subdomains = sublist3r.main(self.domain, 50, savefile=None, ports=None, 
                                       silent=True, verbose=False, enable_bruteforce=False, engines=None)
            subdomains = [s.lower() for s in subdomains]
            print(f"{Fore.GREEN}✓ Sublist3r: {len(subdomains)} subdomains")
            self.results['stats']['tools']['sublist3r'] = len(subdomains)
            return subdomains
        except ImportError:
            print(f"{Fore.YELLOW}⚠ Sublist3r not installed, skipping...")
            return []
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}✗ Sublist3r error: {e}")
            return []
    
    def _run_assetfinder(self) -> List[str]:
        """Run Assetfinder"""
        print(f"{Fore.CYAN}[+] Running Assetfinder...")
        subdomains = []
        try:
            cmd = ["assetfinder", "--subs-only", self.domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            subdomains = [line.strip().lower() for line in result.stdout.split('\n') if line.strip()]
            print(f"{Fore.GREEN}✓ Assetfinder: {len(subdomains)} subdomains")
            self.results['stats']['tools']['assetfinder'] = len(subdomains)
            return subdomains
        except Exception as e:
            if self.config.verbose:
                print(f"{Fore.RED}✗ Assetfinder error: {e}")
            return []
    
    def run_amass_enhanced(self, wordlist_path: str = None) -> List[str]:
        """Enhanced Amass with better control and multiple modes"""
        print(f"{Fore.CYAN}[+] Running Amass...")
        all_subdomains = []
        
        # Different Amass modes
        modes = []
        
        # 1. Passive mode (always)
        modes.append(("passive", ["amass", "enum", "-passive", "-d", self.domain, "-nocolor"]))
        
        # 2. Brute force (if wordlist exists)
        if wordlist_path and os.path.exists(wordlist_path):
            modes.append(("bruteforce", ["amass", "enum", "-brute", "-d", self.domain, 
                                        "-w", wordlist_path, "-nocolor", "-timeout", "30"]))
            
            # 3. Active mode (more aggressive)
            modes.append(("active", ["amass", "enum", "-active", "-d", self.domain, 
                                    "-w", wordlist_path, "-nocolor", "-timeout", "30"]))
        
        for mode_name, cmd in modes:
            try:
                if self.config.verbose:
                    print(f"{Fore.YELLOW}   Running Amass {mode_name} mode...")
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.stdout:
                    found = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    # Filter out non-domain lines
                    found = [s for s in found if '.' in s and not s.startswith(('(', '['))]
                    all_subdomains.extend(found)
                    print(f"{Fore.GREEN}   ✓ Amass {mode_name}: {len(found)} subdomains")
                
            except subprocess.TimeoutExpired:
                print(f"{Fore.YELLOW}   ⚠ Amass {mode_name} timed out")
            except Exception as e:
                if self.config.verbose:
                    print(f"{Fore.RED}   ✗ Amass {mode_name} error: {e}")
        
        # Deduplicate
        unique = list(set([s.lower() for s in all_subdomains]))
        print(f"{Fore.GREEN}✓ Amass total: {len(unique)} unique subdomains")
        self.results['stats']['tools']['amass'] = len(unique)
        return unique
    
    def filter_subdomains(self, raw_subdomains: List[str]) -> Set[str]:
        """Advanced filtering of subdomains"""
        filtered = set()
        
        # Patterns
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        cidr_pattern = re.compile(r'/\d{1,2}$')
        number_only = re.compile(r'^\d+$')
        wildcard_pattern = re.compile(r'^\*\.')
        domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-.]+\.[a-zA-Z]{2,}$')
        
        for sub in raw_subdomains:
            sub = sub.strip().lower()
            
            # Skip empty
            if not sub:
                continue
            
            # Skip IPs
            if ip_pattern.match(sub):
                continue
            
            # Skip CIDR
            if cidr_pattern.search(sub):
                continue
            
            # Skip numbers only
            if number_only.match(sub):
                continue
            
            # Skip wildcards
            if wildcard_pattern.match(sub):
                continue
            
            # Skip if not valid domain format
            if not domain_pattern.match(sub):
                continue
            
            # Skip if domain not in subdomain
            if self.domain not in sub:
                continue
            
            # Clean domain
            if sub.endswith('.'):
                sub = sub[:-1]
            
            # Remove protocol if exists
            if sub.startswith(('http://', 'https://')):
                sub = sub.split('//')[1].split('/')[0]
            
            filtered.add(sub)
        
        return filtered
    
    def get_subdomain_stats(self, subdomains: Set[str]) -> Dict:
        """Get statistics about subdomains"""
        stats = {
            'total': len(subdomains),
            'with_hyphen': len([s for s in subdomains if '-' in s]),
            'with_number': len([s for s in subdomains if any(c.isdigit() for c in s)]),
            'length_distribution': {
                'short': len([s for s in subdomains if len(s) < 10]),
                'medium': len([s for s in subdomains if 10 <= len(s) < 20]),
                'long': len([s for s in subdomains if len(s) >= 20])
            }
        }
        return stats
    
    async def validate_dns_batch(self, subdomains: List[str]) -> Set[str]:
        """Batch DNS validation with async"""
        print(f"{Fore.CYAN}[+] Validating DNS for {len(subdomains)} subdomains...")
        
        valid = set()
        total = len(subdomains)
        
        # Process in batches
        batch_size = 100
        for i in range(0, total, batch_size):
            batch = subdomains[i:i+batch_size]
            tasks = [self.dns_checker.check_async(domain) for domain in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for domain, result in zip(batch, results):
                if isinstance(result, bool) and result:
                    valid.add(domain)
                elif isinstance(result, Exception) and self.config.verbose:
                    print(f"{Fore.RED}✗ Error checking {domain}: {result}")
            
            # Progress
            progress = min(i + batch_size, total)
            self.print_progress(progress, total, f"DNS validation ({len(valid)} valid)")
            
            # Rate limiting
            if i + batch_size < total:
                await asyncio.sleep(0.3)
        
        print()  # New line after progress bar
        print(f"{Fore.GREEN}✓ {len(valid)} valid DNS records found")
        self.results['stats']['dns'] = self.dns_checker.get_stats()
        return valid
    
    async def check_http_async(self, domains: List[str]) -> List[Dict]:
        """Advanced HTTP checking with async"""
        print(f"{Fore.CYAN}[+] Checking HTTP/HTTPS for {len(domains)} domains...")
        
        if not domains:
            return []
        
        results = []
        semaphore = asyncio.Semaphore(self.config.max_workers)
        failed = 0
        
        async def check_single(domain: str):
            async with semaphore:
                return await self._check_http_domain(domain)
        
        tasks = [check_single(domain) for domain in domains]
        http_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in http_results:
            if isinstance(result, dict):
                results.append(result)
            elif isinstance(result, Exception):
                failed += 1
                if self.config.verbose:
                    print(f"{Fore.RED}✗ HTTP error: {str(result)[:50]}")
        
        print(f"{Fore.GREEN}✓ HTTP results: {len(results)} success, {failed} failed")
        self.results['stats']['http'] = {'total': len(domains), 'success': len(results), 'failed': failed}
        return results
    
    async def _check_http_domain(self, domain: str) -> Optional[Dict]:
        """Check single domain HTTP/HTTPS"""
        protocols = ['https://', 'http://']
        
        for proto in protocols:
            url = f"{proto}{domain}"
            
            for attempt in range(self.config.retries):
                try:
                    timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
                    connector = aiohttp.TCPConnector(ssl=False)
                    
                    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
                        headers = {
                            'User-Agent': random.choice(USER_AGENTS),
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.5',
                            'Accept-Encoding': 'gzip, deflate',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '1',
                        }
                        
                        async with session.get(url, headers=headers, allow_redirects=True) as resp:
                            # Get response details
                            status_code = resp.status
                            content_type = resp.headers.get('Content-Type', '')
                            server = resp.headers.get('Server', '')
                            content_length = resp.headers.get('Content-Length', '0')
                            
                            # Get title (if HTML)
                            title = ''
                            if 'text/html' in content_type.lower():
                                try:
                                    html = await resp.text()
                                    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                                    if title_match:
                                        title = title_match.group(1).strip()
                                except:
                                    pass
                            
                            # Detect technologies
                            techs = self._detect_tech(resp.headers, content_type)
                            
                            return {
                                'url': url,
                                'domain': domain,
                                'status_code': status_code,
                                'title': title[:100],
                                'content_type': content_type,
                                'server': server,
                                'content_length': content_length,
                                'tech': techs,
                                'redirects': len(resp.history),
                                'final_url': str(resp.url),
                                'is_active': 200 <= status_code < 400,
                                'response_time': 0,  # Would need more complex timing
                            }
                            
                except asyncio.TimeoutError:
                    if attempt < self.config.retries - 1:
                        await asyncio.sleep(0.5)
                    continue
                except Exception as e:
                    if attempt < self.config.retries - 1:
                        await asyncio.sleep(0.5)
                    continue
        
        return None
    
    def _detect_tech(self, headers: dict, content_type: str) -> List[str]:
        """Detect technologies from headers"""
        techs = []
        
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            techs.append('nginx')
        elif 'apache' in server:
            techs.append('apache')
        elif 'cloudflare' in server or 'cf-ray' in headers:
            techs.append('cloudflare')
        elif 'aws' in server or 'amazon' in server:
            techs.append('aws')
        elif 'microsoft-iis' in server:
            techs.append('iis')
        
        if 'x-powered-by' in headers:
            xpb = headers['x-powered-by'].lower()
            if 'php' in xpb:
                techs.append('php')
            if 'express' in xpb or 'node' in xpb:
                techs.append('node.js')
            if 'asp.net' in xpb:
                techs.append('asp.net')
        
        if 'wordpress' in server or 'wp-' in server:
            techs.append('wordpress')
        
        if 'django' in server:
            techs.append('django')
        
        if 'rails' in server:
            techs.append('rails')
        
        if 'gunicorn' in server:
            techs.append('gunicorn')
        
        # Detect frameworks from headers
        if 'x-frame-options' in headers:
            techs.append('security_headers')
        
        return techs
    
    def _check_http_sync(self, domains: List[str]) -> List[Dict]:
        """Sync HTTP check (fallback)"""
        results = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            future_to_domain = {executor.submit(self._check_http_sync_single, domain): domain 
                               for domain in domains}
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    if self.config.verbose:
                        print(f"{Fore.RED}✗ HTTP sync error: {e}")
        return results
    
    def _check_http_sync_single(self, domain: str) -> Optional[Dict]:
        """Single HTTP check sync"""
        protocols = ['https://', 'http://']
        for proto in protocols:
            url = f"{proto}{domain}"
            try:
                resp = requests.get(url, timeout=self.config.http_timeout, 
                                  headers={'User-Agent': random.choice(USER_AGENTS)},
                                  allow_redirects=True, verify=False)
                return {
                    'url': url,
                    'domain': domain,
                    'status_code': resp.status_code,
                    'title': '',
                    'is_active': 200 <= resp.status_code < 400,
                    'server': resp.headers.get('Server', ''),
                    'content_length': resp.headers.get('Content-Length', '0'),
                    'tech': [],
                    'redirects': len(resp.history)
                }
            except:
                continue
        return None
    
    def _save_enhanced_results(self, results: List[Dict]):
        """Save enhanced results to multiple files"""
        
        # Save detailed results
        with open(os.path.join(self.config.output_dir, "final.txt"), 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"SUBDOMAIN SCAN RESULTS - DETAILED\n")
            f.write(f"Target: {self.domain}\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            # Sort by status code
            results.sort(key=lambda x: x.get('status_code', 0), reverse=True)
            
            active_count = 0
            for r in results:
                status = r.get('status_code', 'N/A')
                if 200 <= status < 400:
                    active_count += 1
                    status_str = f"✅ {status}"
                elif 400 <= status < 500:
                    status_str = f"⚠️ {status}"
                elif status >= 500:
                    status_str = f"❌ {status}"
                else:
                    status_str = f"❓ {status}"
                
                f.write(f"🌐 {r.get('url', 'N/A')}\n")
                f.write(f"   Status: {status_str}\n")
                f.write(f"   Title: {r.get('title', 'No Title')[:100]}\n")
                f.write(f"   Server: {r.get('server', 'Unknown')}\n")
                f.write(f"   Content-Type: {r.get('content_type', 'Unknown')}\n")
                f.write(f"   Tech Stack: {', '.join(r.get('tech', [])) or 'Unknown'}\n")
                f.write(f"   Redirects: {r.get('redirects', 0)}\n")
                f.write(f"   Final URL: {r.get('final_url', r.get('url', 'N/A'))}\n")
                f.write("-"*80 + "\n")
            
            # Summary
            f.write(f"\n📊 SUMMARY:\n")
            f.write(f"   Total tested: {len(results)}\n")
            f.write(f"   Active (200-399): {active_count}\n")
            f.write(f"   Redirects: {len([r for r in results if r.get('redirects', 0) > 0])}\n")
            f.write(f"   Tech detected: {len(set().union(*[set(r.get('tech', [])) for r in results]))}\n")
        
        # Save active only
        with open(os.path.join(self.config.output_dir, "active.txt"), 'w', encoding='utf-8') as f:
            for r in results:
                if r.get('is_active', False):
                    f.write(f"{r.get('url', '')}\n")
                    if r.get('title'):
                        f.write(f"  Title: {r['title'][:100]}\n")
        
        # Save JSON format for automation
        with open(os.path.join(self.config.output_dir, "results.json"), 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.domain,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'stats': self.results['stats'],
                'results': results
            }, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}✓ Detailed results saved to final.txt")
        print(f"{Fore.GREEN}✓ Active URLs saved to active.txt")
        print(f"{Fore.GREEN}✓ JSON results saved to results.json")
    
    async def run_full_scan(self, wordlist_path: str = None):
        """Run full scan with all features"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}🚀 SCANNING: {self.domain}")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Configuration:")
        print(f"  Max Workers: {self.config.max_workers}")
        print(f"  Async: {'Enabled' if self.config.use_async else 'Disabled'}")
        print(f"  DNS Timeout: {self.config.dns_timeout}s")
        print(f"  HTTP Timeout: {self.config.http_timeout}s")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Phase 1: Collect subdomains from all tools
        print(f"\n{Fore.YELLOW}[📡] Phase 1: Collecting subdomains...")
        print(f"{Fore.YELLOW}{'-'*40}")
        all_raw = []
        
        # Run tools
        tools_results = {}
        
        # Subfinder
        tools_results['Subfinder'] = self._run_subfinder()
        all_raw.extend(tools_results['Subfinder'])
        
        # Sublist3r
        tools_results['Sublist3r'] = self._run_sublist3r()
        all_raw.extend(tools_results['Sublist3r'])
        
        # Assetfinder
        tools_results['Assetfinder'] = self._run_assetfinder()
        all_raw.extend(tools_results['Assetfinder'])
        
        # Amass
        tools_results['Amass'] = self.run_amass_enhanced(wordlist_path)
        all_raw.extend(tools_results['Amass'])
        
        # Filter subdomains
        self.results['all_subdomains'] = self.filter_subdomains(all_raw)
        
        # Show statistics
        print(f"\n{Fore.GREEN}📊 Collection Summary:")
        for tool, subs in tools_results.items():
            print(f"   {tool}: {len(subs)}")
        print(f"{Fore.GREEN}   Total unique: {len(self.results['all_subdomains'])}")
        
        # Get detailed stats
        stats = self.get_subdomain_stats(self.results['all_subdomains'])
        print(f"\n{Fore.CYAN}📈 Subdomain Statistics:")
        print(f"   Total: {stats['total']}")
        print(f"   With hyphen: {stats['with_hyphen']}")
        print(f"   With numbers: {stats['with_number']}")
        print(f"   Short (<10 chars): {stats['length_distribution']['short']}")
        print(f"   Medium (10-19 chars): {stats['length_distribution']['medium']}")
        print(f"   Long (20+ chars): {stats['length_distribution']['long']}")
        
        if len(self.results['all_subdomains']) == 0:
            print(f"{Fore.RED}✗ No subdomains found. Exiting.")
            sys.exit(1)
        
        # Phase 2: Validate DNS
        print(f"\n{Fore.YELLOW}[🔍] Phase 2: Validating DNS...")
        print(f"{Fore.YELLOW}{'-'*40}")
        if self.config.use_async:
            self.results['valid_dns'] = await self.validate_dns_batch(list(self.results['all_subdomains']))
        else:
            # Sync fallback
            print(f"{Fore.YELLOW}Using sync DNS validation...")
            valid = set()
            total = len(self.results['all_subdomains'])
            for i, sub in enumerate(self.results['all_subdomains']):
                if self.dns_checker.check_sync(sub):
                    valid.add(sub)
                self.print_progress(i+1, total, f"DNS validation ({len(valid)} valid)")
            print()
            self.results['valid_dns'] = valid
            print(f"{Fore.GREEN}✓ {len(valid)} valid DNS records found")
        
        # Phase 3: Save all subs
        print(f"\n{Fore.YELLOW}[💾] Phase 3: Saving results...")
        with open(os.path.join(self.config.output_dir, "subs.txt"), 'w', encoding='utf-8') as f:
            for sub in sorted(self.results['all_subdomains']):
                f.write(sub + '\n')
        print(f"{Fore.GREEN}✓ All subdomains saved to subs.txt ({len(self.results['all_subdomains'])})")
        
        # Phase 4: HTTP check
        if self.results['valid_dns']:
            print(f"\n{Fore.YELLOW}[🌐] Phase 4: HTTP/HTTPS validation...")
            print(f"{Fore.YELLOW}{'-'*40}")
            
            if self.config.use_async:
                http_results = await self.check_http_async(list(self.results['valid_dns']))
            else:
                # Sync HTTP check
                http_results = self._check_http_sync(list(self.results['valid_dns']))
            
            # Filter active
            active = [r for r in http_results if r.get('is_active', False)]
            self.results['http_results'] = http_results
            
            # Save detailed results
            self._save_enhanced_results(http_results)
            
            # Summary
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}✅ SCAN COMPLETE!")
            print(f"{Fore.GREEN}{'='*60}")
            print(f"📊 Final Statistics:")
            print(f"   Total found: {len(self.results['all_subdomains'])}")
            print(f"   Valid DNS: {len(self.results['valid_dns'])}")
            print(f"   HTTP/HTTPS alive: {len(active)}")
            print(f"   Total checked: {len(http_results)}")
            
            # DNS stats
            dns_stats = self.results['stats'].get('dns', {})
            if dns_stats:
                print(f"   DNS queries: {dns_stats.get('total', 0)}")
                print(f"   DNS valid: {dns_stats.get('valid', 0)}")
            
            print(f"\n📁 Output files:")
            print(f"   - subs.txt (all subdomains) - {len(self.results['all_subdomains'])}")
            print(f"   - final.txt (detailed results) - {len(http_results)}")
            print(f"   - active.txt (active HTTP/HTTPS) - {len(active)}")
            print(f"   - results.json (JSON format) - {len(http_results)}")
            
            # Total time
            elapsed = time.time() - self.start_time
            print(f"\n⏱️  Total scan time: {elapsed:.2f} seconds")
            print(f"{Fore.GREEN}{'='*60}")
        else:
            print(f"{Fore.RED}✗ No valid DNS records found")
            sys.exit(1)

def create_default_wordlist_enhanced() -> str:
    """Create enhanced default wordlist"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wordlist_path = os.path.join(base_dir, "wordlist.txt")
    
    if os.path.exists(wordlist_path) and os.path.getsize(wordlist_path) > 100:
        return wordlist_path
    
    print(f"{Fore.CYAN}[+] Creating enhanced default wordlist...")
    
    # Comprehensive wordlist
    common_words = [
        # Basic
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
        "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
        
        # Services
        "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
        "web", "media", "email", "images", "img", "www1", "intranet", "portal",
        "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3",
        
        # Development
        "dns", "search", "ftp2", "test2", "xmpp", "mx1", "mail1", "webmail2",
        "mssql", "telnet", "remote", "ssh", "git", "crm", "erp", "jenkins", "jira",
        "confluence", "bitbucket", "gitlab", "sonar", "nexus", "artifactory",
        
        # Security
        "firewall", "proxy", "vpn", "radius", "ldap", "samba", "ntp",
        "syslog", "snmp", "sftp", "scp", "rdp", "vnc", "xen", "kvm",
        
        # Cloud & Infrastructure
        "aws", "azure", "gcp", "cloud", "container", "docker", "k8s", "kubernetes",
        "openshift", "elastic", "kibana", "grafana", "prometheus", "monitoring",
        "logging", "backup", "restore", "archive", "storage", "database", "db",
        "redis", "memcached", "mongodb", "postgres", "mysql", "mariadb",
        
        # Additional
        "stage", "staging", "prod", "production", "qa", "quality", "uat", "testing",
        "sandbox", "playground", "demo", "trial", "test", "dev", "develop", "development",
        "dashboard", "panel", "control", "manage", "manager", "management",
        "status", "health", "metrics", "analytics", "reports", "reporting"
    ]
    
    with open(wordlist_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(common_words))
    
    print(f"{Fore.GREEN}✓ Wordlist created: {wordlist_path} ({len(common_words)} words)")
    return wordlist_path

async def merge_wordlists_async(wordlists: List[str]) -> Optional[str]:
    """Async merge multiple wordlists"""
    print(f"{Fore.CYAN}[+] Merging {len(wordlists)} wordlists...")
    
    all_words = set()
    for wl in wordlists:
        try:
            if wl.startswith(('http://', 'https://')):
                # Download from URL
                temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
                print(f"{Fore.YELLOW}   Downloading: {wl}")
                urllib.request.urlretrieve(wl, temp_file.name)
                wl = temp_file.name
            
            with open(wl, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip().lower() for line in f if line.strip()]
                all_words.update(words)
                print(f"{Fore.GREEN}   ✓ Added {len(words)} words from {os.path.basename(wl)}")
                
        except Exception as e:
            print(f"{Fore.RED}   ✗ Error: {e}")
    
    if all_words:
        merged_path = tempfile.NamedTemporaryFile(delete=False, suffix='.txt').name
        with open(merged_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(all_words)))
        print(f"{Fore.GREEN}✓ Merged {len(all_words)} unique words")
        return merged_path
    
    return None

def check_required_tools():
    """Check if required tools are installed"""
    print(f"{Fore.CYAN}[+] Checking required tools...")
    
    tools = {
        'subfinder': 'subfinder -version',
        'assetfinder': 'assetfinder --help',
        'amass': 'amass -version',
        'go': 'go version'  # Needed for installing tools
    }
    
    installed = []
    missing = []
    
    for tool, cmd in tools.items():
        try:
            subprocess.run(cmd.split(), capture_output=True, check=True)
            print(f"{Fore.GREEN}   ✓ {tool}")
            installed.append(tool)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{Fore.RED}   ✗ {tool}")
            missing.append(tool)
    
    # Check Sublist3r separately
    try:
        import sublist3r
        print(f"{Fore.GREEN}   ✓ sublist3r")
        installed.append('sublist3r')
    except ImportError:
        print(f"{Fore.RED}   ✗ sublist3r")
        missing.append('sublist3r')
    
    return installed, missing

def install_missing_tools(missing: List[str]):
    """Install missing tools"""
    if not missing:
        return
    
    print(f"\n{Fore.YELLOW}[+] Installing missing tools: {', '.join(missing)}")
    
    install_commands = {
        'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
        'amass': 'go install -v github.com/owasp-amass/amass/v4/...@master',
        'sublist3r': 'pip install sublist3r'
    }
    
    for tool in missing:
        if tool in install_commands:
            print(f"{Fore.CYAN}   Installing {tool}...")
            try:
                subprocess.run(install_commands[tool], shell=True, check=True)
                print(f"{Fore.GREEN}   ✓ {tool} installed")
            except Exception as e:
                print(f"{Fore.RED}   ✗ Failed to install {tool}: {e}")

def print_banner():
    """Print beautiful banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                               ║
{Fore.CYAN}║     {Style.BRIGHT}🚀 Subdomain Scanner v3.0 - Professional{Fore.CYAN}             ║
{Fore.CYAN}║     {Style.DIM}Advanced Multi-Threaded Subdomain Discovery{Fore.CYAN}              ║
{Fore.CYAN}║     {Style.DIM}DNS + HTTP Validation + Async Processing{Fore.CYAN}                ║
{Fore.CYAN}║                                                               ║
{Fore.CYAN}║     {Fore.GREEN}Tools:{Fore.CYAN} Subfinder | Sublist3r | Assetfinder | Amass     ║
{Fore.CYAN}║     {Fore.YELLOW}Features:{Fore.CYAN} DNS Validation | HTTP Check | Tech Detection ║
{Fore.CYAN}║                                                               ║
{Fore.CYAN}╚═══════════════════════════════════════════════════════════════╝
{Fore.RESET}
"""
    print(banner)

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user")
    print(f"{Fore.CYAN}Exiting gracefully...")
    sys.exit(0)

def main():
    """Main function"""
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Print banner
    print_banner()
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Advanced Subdomain Scanner v3.0 - Professional Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}═══════════════════════════════════════════════════════════════════
{Fore.CYAN}📖 EXAMPLES:
{Fore.CYAN}═══════════════════════════════════════════════════════════════════

{Fore.GREEN}Basic Usage:
{Fore.YELLOW}  subdomain-scanner example.com

{Fore.GREEN}With Custom Wordlist:
{Fore.YELLOW}  subdomain-scanner example.com -w /path/to/wordlist.txt

{Fore.GREEN}With Multiple Wordlists:
{Fore.YELLOW}  subdomain-scanner example.com -w wl1.txt,wl2.txt,wl3.txt

{Fore.GREEN}With Popular Wordlists:
{Fore.YELLOW}  subdomain-scanner example.com --use-seclists
{Fore.YELLOW}  subdomain-scanner example.com --use-all

{Fore.GREEN}Performance Tuning:
{Fore.YELLOW}  subdomain-scanner example.com --max-workers 100 --timeout 10

{Fore.GREEN}Passive Mode (No Wordlist):
{Fore.YELLOW}  subdomain-scanner example.com --no-wordlist

{Fore.GREEN}Verbose Debug:
{Fore.YELLOW}  subdomain-scanner example.com --verbose

{Fore.CYAN}═══════════════════════════════════════════════════════════════════
{Fore.CYAN}📁 OUTPUT FILES:
{Fore.CYAN}═══════════════════════════════════════════════════════════════════
{Fore.YELLOW}  subs.txt     {Fore.WHITE}- All discovered subdomains
{Fore.YELLOW}  final.txt    {Fore.WHITE}- Detailed results with status, title, tech
{Fore.YELLOW}  active.txt   {Fore.WHITE}- Active HTTP/HTTPS subdomains only
{Fore.YELLOW}  results.json {Fore.WHITE}- JSON format for automation

{Fore.CYAN}═══════════════════════════════════════════════════════════════════
{Fore.CYAN}🔧 TROUBLESHOOTING:
{Fore.CYAN}═══════════════════════════════════════════════════════════════════
{Fore.YELLOW}  If tools are missing: {Fore.WHITE}The script will attempt to install them
{Fore.YELLOW}  If scan is slow: {Fore.WHITE}Try --max-workers 20 --timeout 15
{Fore.YELLOW}  If scan hangs: {Fore.WHITE}Try --no-async
{Fore.YELLOW}  For more help: {Fore.WHITE}subdomain-scanner -h
{Fore.RESET}
"""
    )
    
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('-w', '--wordlist', help='Wordlist file(s) - separate with commas, supports URLs')
    parser.add_argument('--use-seclists', action='store_true', help='Download and use SecLists wordlist')
    parser.add_argument('--use-all', action='store_true', help='Download and use all popular wordlists')
    parser.add_argument('--no-wordlist', action='store_true', help='Disable wordlist (passive mode only)')
    parser.add_argument('--max-workers', type=int, default=50, help='Maximum concurrent workers (default: 50)')
    parser.add_argument('--timeout', type=int, default=8, help='HTTP timeout in seconds (default: 8)')
    parser.add_argument('--dns-timeout', type=int, default=5, help='DNS timeout in seconds (default: 5)')
    parser.add_argument('--no-async', action='store_true', help='Disable async processing')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--output-dir', default='.', help='Output directory (default: current)')
    parser.add_argument('--version', action='version', version='Subdomain Scanner v3.0')
    parser.add_argument('--no-progress', action='store_true', help='Disable progress bar')
    
    args = parser.parse_args()
    
    # Check and install tools
    installed, missing = check_required_tools()
    if missing:
        install_missing_tools(missing)
    
    # Config
    config = ScanConfig(
        max_workers=args.max_workers,
        dns_timeout=args.dns_timeout,
        http_timeout=args.timeout,
        use_async=not args.no_async,
        verbose=args.verbose,
        output_dir=args.output_dir,
        show_progress=not args.no_progress
    )
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Wordlist handling
    wordlist_path = None
    if not args.no_wordlist:
        wordlist_path = create_default_wordlist_enhanced()
        
        if args.wordlist:
            # Handle multiple wordlists
            wordlists = args.wordlist.split(',')
            if len(wordlists) > 1:
                # Merge wordlists asynchronously
                try:
                    merged = asyncio.run(merge_wordlists_async(wordlists))
                    if merged:
                        wordlist_path = merged
                except Exception as e:
                    print(f"{Fore.RED}Error merging wordlists: {e}")
            else:
                wordlist_path = wordlists[0]
                
                # If URL, download it
                if wordlist_path.startswith(('http://', 'https://')):
                    try:
                        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
                        print(f"{Fore.YELLOW}Downloading wordlist from: {wordlist_path}")
                        urllib.request.urlretrieve(wordlist_path, temp_file.name)
                        wordlist_path = temp_file.name
                        print(f"{Fore.GREEN}✓ Downloaded to: {wordlist_path}")
                    except Exception as e:
                        print(f"{Fore.RED}✗ Failed to download wordlist: {e}")
                        wordlist_path = create_default_wordlist_enhanced()
        
        # Add popular wordlists
        if args.use_seclists or args.use_all:
            sources = []
            if args.use_seclists:
                sources.append(POPULAR_WORDLISTS['seclists'])
            if args.use_all:
                sources.extend(list(POPULAR_WORDLISTS.values()))
            
            if sources:
                try:
                    merged = asyncio.run(merge_wordlists_async(sources))
                    if merged:
                        wordlist_path = merged
                except Exception as e:
                    print(f"{Fore.RED}Error merging popular wordlists: {e}")
    
    # Scanner
    scanner = SubdomainScanner(args.domain, config)
    
    # Run scan
    try:
        asyncio.run(scanner.run_full_scan(wordlist_path))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
