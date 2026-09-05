#!/usr/bin/env python3
"""
SIATK - Subdomain Intelligence & Asset Toolkit
Authorized security reconnaissance and subdomain enumeration aggregator
"""

import argparse
import re
import os
import sys
import time
import json
import shutil
import signal
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Set, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from threading import Thread, Event
from collections import deque
import urllib.parse

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    CLEAR_LINE = '\033[2K\r'
    UP = '\033[1A'

@dataclass
class ToolResult:
    """Represents the result of a tool execution"""
    tool_name: str
    results: Set[str] = field(default_factory=set)
    raw_output: str = ""
    stderr: str = ""
    status: str = "pending"  # pending, running, done, timeout, failed, skipped
    elapsed_time: float = 0.0
    start_time: float = 0.0
    end_time: float = 0.0
    timed_out: bool = False
    exit_code: int = -1

@dataclass
class Config:
    """Configuration for the SIATK pipeline"""
    target: str = ""
    wordlist: Optional[str] = None
    threads: int = 10
    output_mode: str = "combined"
    time_minutes: int = 10
    output_dir: str = ""
    timestamp: str = ""

class SIATK:
    """Main SIATK application class"""
    
    def __init__(self):
        self.config = Config()
        self.tool_results: Dict[str, ToolResult] = {}
        self.all_hosts: Set[str] = set()
        self.live_urls: Set[str] = set()
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.is_tty = sys.stdout.isatty()
        self.running_processes: List[subprocess.Popen] = []
        self.shutdown_event = Event()
        
        # ASCII Art
        self.logo = f"""
{Colors.CYAN}    ███████╗██╗ █████╗ ████████╗██╗  ██╗
    ██╔════╝██║██╔══██╗╚══██╔══╝██║ ██╔╝
    ███████╗██║███████║   ██║   █████╔╝ 
    ╚════██║██║██╔══██║   ██║   ██╔═██╗ 
    ███████║██║██║  ██║   ██║   ██║  ██╗
    ╚══════╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝{Colors.RESET}
{Colors.WHITE}{Colors.BOLD}    Subdomain Intelligence & Asset Toolkit{Colors.RESET}
{Colors.DIM}    v1.0 - Authorized Security Reconnaissance Tool{Colors.RESET}
"""
    
    def log(self, message: str, level: str = "INFO", color: str = Colors.WHITE):
        """Log a message to console with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if self.is_tty:
            sys.stderr.write(f"{Colors.DIM}[{timestamp}]{Colors.RESET} {color}{message}{Colors.RESET}\n")
        else:
            sys.stderr.write(f"[{timestamp}] {message}\n")
        sys.stderr.flush()

    def print_status_line(self, message: str, clear: bool = True):
        """Print a status line with ANSI control sequences"""
        if self.is_tty:
            if clear:
                sys.stdout.write(f"{Colors.CLEAR_LINE}{message}")
            else:
                sys.stdout.write(f"\n{message}")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"{message}\n")
            sys.stdout.flush()

    def clear_last_line(self):
        """Clear the last line in terminal"""
        if self.is_tty:
            sys.stdout.write(f"{Colors.CLEAR_LINE}")
            sys.stdout.flush()

    def print_help(self):
        """Print help information"""
        help_text = f"""
{Colors.BOLD}{Colors.CYAN}SYNOPSIS{Colors.RESET}
    python3 enum.py -u <domain> [OPTIONS]

{Colors.BOLD}{Colors.CYAN}REQUIRED{Colors.RESET}
    -u, --url <domain>     Target root domain (e.g., example.com)

{Colors.BOLD}{Colors.CYAN}OPTIONS{Colors.RESET}
    -w, --wordlist <file>  Wordlist for dnscan ONLY
    -t, --threads <num>    Number of threads (default: 10)
    -o, --output <mode>    Output mode: combined, all (default: combined)
    --time-minutes <num>   Maximum runtime in minutes (default: 10)
    -h, --help            Show this help message

{Colors.BOLD}{Colors.CYAN}EXAMPLES{Colors.RESET}
    python3 enum.py -u example.com
    python3 enum.py -u example.com -t 20
    python3 enum.py -u example.com -w wordlist.txt
    python3 enum.py -u example.com -o all
    python3 enum.py -u example.com --time-minutes=5
    python3 enum.py -u example.com -t 20 -w wordlist.txt -o all --time-minutes=5

{Colors.BOLD}{Colors.CYAN}OUTPUT MODES{Colors.RESET}
    {Colors.YELLOW}combined{Colors.RESET} (default)
        all.txt - All unique subdomains found
        live.txt - Live HTTP/HTTPS URLs
        screenshots/ - Screenshots of live URLs

    {Colors.YELLOW}all{Colors.RESET}
        amass.txt, subfinder.txt, assetfinder.txt, sublist3r.txt, dnscan.txt
        all.txt, live.txt, screenshots/
        logs/ - Detailed execution logs

{Colors.BOLD}{Colors.CYAN}TIMEOUT BEHAVIOR{Colors.RESET}
    • Amass, Subfinder, Assetfinder, Sublist3r, dnscan, httpx use the timeout
    • Gowitness runs WITHOUT timeout to complete screenshots naturally
"""
        print(help_text)

    def normalize_target(self, target: str) -> str:
        """Normalize the target domain"""
        # Remove protocol
        target = re.sub(r'^https?://', '', target)
        # Remove paths, query strings, fragments
        target = target.split('/')[0]
        target = target.split('?')[0]
        target = target.split('#')[0]
        # Remove trailing dot
        target = target.rstrip('.')
        # Remove trailing slash
        target = target.rstrip('/')
        # Lowercase
        target = target.lower()
        return target

    def validate_target(self, target: str) -> bool:
        """Validate the target is a proper hostname"""
        # Basic hostname validation
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(pattern, target):
            return True
        # Allow subdomains with more labels
        if re.match(r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,}$', target):
            return True
        return False

    def is_in_scope(self, hostname: str, root_domain: str) -> bool:
        """Check if a hostname is within the target scope"""
        hostname = hostname.lower().strip()
        root = root_domain.lower().strip()
        
        if not hostname or not root:
            return False
            
        # Exact match
        if hostname == root:
            return True
            
        # Subdomain match
        if hostname.endswith('.' + root):
            return True
            
        return False

    def extract_domains(self, text: str, root_domain: str) -> Set[str]:
        """Extract valid in-scope domains from text"""
        domains = set()
        
        # Pattern to match hostnames (including subdomains)
        # More conservative pattern to avoid false positives
        pattern = r'(?i)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})'
        
        for match in re.finditer(pattern, text):
            potential = match.group(0).lower()
            
            # Clean up potential
            potential = potential.rstrip('.,;:!?"\'')
            potential = potential.lstrip('.,;:!?"\'')
            
            # Basic validation
            if len(potential) < 3:
                continue
                
            # Check if it's in scope
            if self.is_in_scope(potential, root_domain):
                domains.add(potential)
                
        return domains

    def filter_domains(self, domains: Set[str], root_domain: str) -> Set[str]:
        """Filter domains to only include those in scope"""
        return {d for d in domains if self.is_in_scope(d, root_domain)}

    def normalize_hostname(self, hostname: str) -> str:
        """Normalize a hostname"""
        hostname = hostname.lower().strip()
        # Remove surrounding quotes or brackets
        hostname = hostname.strip('"\'. ')
        # Remove trailing punctuation
        hostname = hostname.rstrip('.,;:!?')
        return hostname

    def filter_live_urls(self, urls: Set[str], root_domain: str) -> Set[str]:
        """Filter URLs to only include valid HTTP/HTTPS in-scope URLs"""
        valid_urls = set()
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                
                # Only http and https
                if parsed.scheme not in ['http', 'https']:
                    continue
                    
                # Validate hostname
                hostname = parsed.hostname
                if not hostname:
                    continue
                    
                # Check if in scope
                if not self.is_in_scope(hostname, root_domain):
                    continue
                    
                # Reconstruct URL
                clean_url = f"{parsed.scheme}://{parsed.hostname}"
                if parsed.port and parsed.port not in [80, 443]:
                    clean_url += f":{parsed.port}"
                if parsed.path and parsed.path != '/':
                    clean_url += parsed.path
                    
                valid_urls.add(clean_url)
                
            except Exception:
                continue
                
        return valid_urls

    def command_exists(self, cmd: str) -> bool:
        """Check if a command exists in PATH"""
        return shutil.which(cmd) is not None

    def preflight_check(self) -> bool:
        """Check all required dependencies"""
        required_commands = ['amass', 'subfinder', 'assetfinder', 'sublist3r', 
                           'dnscan', 'httpx', 'gowitness']
        
        missing = []
        for cmd in required_commands:
            if not self.command_exists(cmd):
                missing.append(cmd)
        
        if missing:
            self.log(f"Missing required tools: {', '.join(missing)}", "ERROR", Colors.RED)
            self.log("Please install missing tools and try again.", "ERROR", Colors.RED)
            return False
        
        return True

    def build_amass_command(self, target: str, timeout_minutes: int, threads: int) -> List[str]:
        """Build the Amass command"""
        return [
            'amass', 'enum',
            '-d', target,
            '-timeout', str(timeout_minutes),
            '-max-dns-queries', str(max(1, threads * 2)),
            '-o', '/dev/null'  # We capture stdout separately
        ]

    def build_subfinder_command(self, target: str, timeout_minutes: int, threads: int) -> List[str]:
        """Build the Subfinder command"""
        return [
            'subfinder',
            '-d', target,
            '-all',
            '-silent',
            '-nc',
            '-max-time', str(timeout_minutes),
            '-t', str(min(threads, 100))  # Subfinder has a max of 100
        ]

    def build_assetfinder_command(self, target: str) -> List[str]:
        """Build the Assetfinder command"""
        return [
            'assetfinder',
            '--subs-only',
            target
        ]

    def build_sublist3r_command(self, target: str, threads: int) -> List[str]:
        """Build the Sublist3r command"""
        return [
            'sublist3r',
            '-d', target,
            '-t', str(min(threads, 50)),  # Sublist3r has threading limitations
            '-v'  # Verbose to get output we can parse
        ]

    def build_dnscan_command(self, target: str, wordlist: str, threads: int) -> List[str]:
        """Build the dnscan command"""
        # dnscan uses -d for domain and -w for wordlist
        # Clamp threads to safe maximum for dnscan
        safe_threads = min(threads, 20)
        return [
            'dnscan',
            '-d', target,
            '-w', wordlist,
            '-t', str(safe_threads)
        ]

    def build_httpx_command(self, target_file: str, threads: int, timeout_minutes: int) -> List[str]:
        """Build the httpx command"""
        # Convert minutes to seconds for httpx
        timeout_seconds = timeout_minutes * 60
        return [
            'httpx',
            '-l', target_file,
            '-silent',
            '-fr',
            '-t', str(threads),
            '-timeout', str(timeout_seconds),
            '-retries', '2',
            '-nc'
        ]

    def build_gowitness_command(self, url_file: str, threads: int) -> List[str]:
        """Build the Gowitness command"""
        return [
            'gowitness',
            'scan',
            'file',
            '-f', url_file,
            '--screenshot-path', './screenshots/',
            '--threads', str(min(threads, 20))
        ]

    def run_tool(self, tool_name: str, cmd: List[str], timeout_seconds: Optional[int] = None, 
                 capture_output: bool = True) -> ToolResult:
        """Run a tool with timeout support"""
        result = ToolResult(tool_name=tool_name)
        result.status = "running"
        result.start_time = time.time()
        
        stdout_file = None
        stderr_file = None
        process = None
        
        try:
            if capture_output:
                # Use temporary files for stdout/stderr
                stdout_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                stderr_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
                
                process = subprocess.Popen(
                    cmd,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                    text=True
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    text=True
                )
            
            self.running_processes.append(process)
            
            # Wait for process with timeout
            start_time = time.time()
            while True:
                if self.shutdown_event.is_set():
                    self.kill_process_group(process)
                    break
                    
                try:
                    if timeout_seconds is not None:
                        elapsed = time.time() - start_time
                        if elapsed >= timeout_seconds:
                            self.kill_process_group(process)
                            result.timed_out = True
                            result.status = "timeout"
                            break
                    
                    # Check if process has finished
                    if process.poll() is not None:
                        break
                        
                    # Update elapsed time
                    result.elapsed_time = time.time() - result.start_time
                    time.sleep(0.1)
                    
                except Exception:
                    break
            
            # Wait for process to finish
            try:
                result.exit_code = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.kill_process_group(process)
                result.exit_code = process.wait()
            
            # Read output from temporary files
            if capture_output and stdout_file:
                stdout_file.flush()
                stdout_file.close()
                with open(stdout_file.name, 'r') as f:
                    result.raw_output = f.read()
                os.unlink(stdout_file.name)
                
            if capture_output and stderr_file:
                stderr_file.flush()
                stderr_file.close()
                with open(stderr_file.name, 'r') as f:
                    result.stderr = f.read()
                os.unlink(stderr_file.name)
            elif not capture_output and process:
                stdout, stderr = process.communicate()
                result.raw_output = stdout
                result.stderr = stderr
            
            result.elapsed_time = time.time() - result.start_time
            result.end_time = time.time()
            
            if not result.timed_out and result.exit_code == 0:
                result.status = "done"
                
        except FileNotFoundError:
            result.status = "failed"
            result.exit_code = -1
            self.log(f"Command not found: {cmd[0]}", "ERROR", Colors.RED)
        except Exception as e:
            result.status = "failed"
            result.exit_code = -1
            self.log(f"Error running {tool_name}: {str(e)}", "ERROR", Colors.RED)
        finally:
            if process and process in self.running_processes:
                self.running_processes.remove(process)
            if stdout_file and os.path.exists(stdout_file.name):
                try:
                    os.unlink(stdout_file.name)
                except:
                    pass
            if stderr_file and os.path.exists(stderr_file.name):
                try:
                    os.unlink(stderr_file.name)
                except:
                    pass
                
        return result

    def kill_process_group(self, process: subprocess.Popen):
        """Kill an entire process group"""
        if process is None:
            return
            
        try:
            # Send SIGTERM to process group
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            # Give it a moment to terminate gracefully
            time.sleep(1)
            
            # If still running, send SIGKILL
            if process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                time.sleep(0.5)
        except ProcessLookupError:
            pass
        except Exception:
            pass

    def update_status_display(self, step: int, total_steps: int, tool_name: str, 
                             result: ToolResult, status_message: str = ""):
        """Update the status display with current progress"""
        if not self.is_tty:
            return
            
        status_lines = []
        
        # Main status header
        if step <= total_steps:
            status_lines.append(f"{Colors.BOLD}{Colors.CYAN}[{step}/{total_steps}] {tool_name}{Colors.RESET}")
            
            if result:
                if result.status == "running":
                    elapsed = time.time() - result.start_time
                    elapsed_str = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
                    timeout_str = f"{self.config.time_minutes}m"
                    results_count = len(result.results)
                    status_lines.append(f"  {Colors.YELLOW}├─ Status:{Colors.RESET} {Colors.GREEN}RUNNING{Colors.RESET}")
                    status_lines.append(f"  {Colors.YELLOW}├─ Elapsed:{Colors.RESET} {elapsed_str}")
                    status_lines.append(f"  {Colors.YELLOW}├─ Results:{Colors.RESET} {results_count}")
                    status_lines.append(f"  {Colors.YELLOW}└─ Timeout:{Colors.RESET} {timeout_str}")
                    
                elif result.status == "done":
                    status_lines.append(f"  {Colors.YELLOW}└─{Colors.RESET} {Colors.GREEN}DONE{Colors.RESET} — {len(result.results)} results")
                    
                elif result.status == "timeout":
                    status_lines.append(f"  {Colors.YELLOW}└─{Colors.RESET} {Colors.RED}TIMEOUT{Colors.RESET} — {len(result.results)} results preserved")
                    
                elif result.status == "failed":
                    status_lines.append(f"  {Colors.YELLOW}└─{Colors.RESET} {Colors.RED}FAILED{Colors.RESET}")
                    
                elif result.status == "skipped":
                    status_lines.append(f"  {Colors.YELLOW}└─{Colors.RESET} {Colors.DIM}SKIPPED{Colors.RESET}")
        
        # Clear previous status lines and print new ones
        # Move up to start of status block
        lines_to_clear = len(self._last_status_lines) if hasattr(self, '_last_status_lines') else 0
        for _ in range(lines_to_clear):
            sys.stdout.write(f"{Colors.UP}{Colors.CLEAR_LINE}")
        
        # Print new status
        for line in status_lines:
            sys.stdout.write(f"{line}\n")
        
        sys.stdout.flush()
        self._last_status_lines = status_lines

    def write_clean_results(self, results: Set[str], filename: str):
        """Write clean results to a file"""
        sorted_results = sorted(results)
        with open(filename, 'w') as f:
            for item in sorted_results:
                f.write(f"{item}\n")

    def run_pipeline(self):
        """Run the complete enumeration pipeline"""
        target = self.config.target
        output_dir = self.config.output_dir
        output_mode = self.config.output_mode
        threads = self.config.threads
        time_minutes = self.config.time_minutes
        
        # Create directories
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        Path(os.path.join(output_dir, 'screenshots')).mkdir(exist_ok=True)
        
        if output_mode == 'all':
            Path(os.path.join(output_dir, 'logs')).mkdir(exist_ok=True)
        
        # Initialize results
        all_hosts = set()
        tool_results = {}
        
        # Define tools to run
        tools = [
            ('Amass', 'amass'),
            ('Subfinder', 'subfinder'),
            ('Assetfinder', 'assetfinder'),
            ('Sublist3r', 'sublist3r'),
            ('dnscan', 'dnscan')
        ]
        
        total_steps = len(tools) + 2  # +2 for httpx and gowitness
        
        # Display logo
        if self.is_tty:
            print(self.logo)
            print(f"{Colors.DIM}Target: {Colors.WHITE}{target}{Colors.RESET}")
            print(f"{Colors.DIM}Output: {Colors.WHITE}{output_dir}{Colors.RESET}")
            print(f"{Colors.DIM}Timeout:{Colors.RESET} {time_minutes}m")
            print("")
        
        # Step 1: Amass
        step = 1
        result = ToolResult(tool_name='Amass')
        
        self.log(f"Starting Amass enumeration...", "INFO", Colors.CYAN)
        self.update_status_display(step, total_steps, 'AMASS', result)
        
        cmd = self.build_amass_command(target, time_minutes, threads)
        result = self.run_tool('Amass', cmd, timeout_seconds=time_minutes * 60)
        
        # Extract domains from raw output
        if result.raw_output:
            domains = self.extract_domains(result.raw_output, target)
            result.results = self.filter_domains(domains, target)
            all_hosts.update(result.results)
        
        tool_results['Amass'] = result
        self.update_status_display(step, total_steps, 'AMASS', result)
        
        # Step 2: Subfinder
        step = 2
        result = ToolResult(tool_name='Subfinder')
        
        self.log(f"Starting Subfinder enumeration...", "INFO", Colors.CYAN)
        self.update_status_display(step, total_steps, 'SUBFINDER', result)
        
        cmd = self.build_subfinder_command(target, time_minutes, threads)
        result = self.run_tool('Subfinder', cmd, timeout_seconds=time_minutes * 60)
        
        if result.raw_output:
            domains = self.extract_domains(result.raw_output, target)
            result.results = self.filter_domains(domains, target)
            all_hosts.update(result.results)
        
        tool_results['Subfinder'] = result
        self.update_status_display(step, total_steps, 'SUBFINDER', result)
        
        # Step 3: Assetfinder
        step = 3
        result = ToolResult(tool_name='Assetfinder')
        
        self.log(f"Starting Assetfinder enumeration...", "INFO", Colors.CYAN)
        self.update_status_display(step, total_steps, 'ASSETFINDER', result)
        
        cmd = self.build_assetfinder_command(target)
        result = self.run_tool('Assetfinder', cmd, timeout_seconds=time_minutes * 60)
        
        if result.raw_output:
            domains = self.extract_domains(result.raw_output, target)
            result.results = self.filter_domains(domains, target)
            all_hosts.update(result.results)
        
        tool_results['Assetfinder'] = result
        self.update_status_display(step, total_steps, 'ASSETFINDER', result)
        
        # Step 4: Sublist3r
        step = 4
        result = ToolResult(tool_name='Sublist3r')
        
        self.log(f"Starting Sublist3r enumeration...", "INFO", Colors.CYAN)
        self.update_status_display(step, total_steps, 'SUBLIST3R', result)
        
        cmd = self.build_sublist3r_command(target, threads)
        result = self.run_tool('Sublist3r', cmd, timeout_seconds=time_minutes * 60)
        
        if result.raw_output:
            domains = self.extract_domains(result.raw_output, target)
            result.results = self.filter_domains(domains, target)
            all_hosts.update(result.results)
        
        tool_results['Sublist3r'] = result
        self.update_status_display(step, total_steps, 'SUBLIST3R', result)
        
        # Step 5: dnscan
        step = 5
        result = ToolResult(tool_name='dnscan')
        
        if self.config.wordlist and os.path.exists(self.config.wordlist):
            self.log(f"Starting dnscan enumeration with wordlist...", "INFO", Colors.CYAN)
            self.update_status_display(step, total_steps, 'DNSCAN', result)
            
            cmd = self.build_dnscan_command(target, self.config.wordlist, threads)
            result = self.run_tool('dnscan', cmd, timeout_seconds=time_minutes * 60)
            
            if result.raw_output:
                domains = self.extract_domains(result.raw_output, target)
                result.results = self.filter_domains(domains, target)
                all_hosts.update(result.results)
        else:
            result.status = "skipped"
            self.log(f"dnscan skipped - no wordlist provided", "INFO", Colors.YELLOW)
            
        tool_results['dnscan'] = result
        self.update_status_display(step, total_steps, 'DNSCAN', result)
        
        # Step 6: Save all.txt
        step = 6
        self.log(f"Combining and deduplicating all results...", "INFO", Colors.CYAN)
        
        # Global deduplication
        all_hosts = {self.normalize_hostname(h) for h in all_hosts if h}
        all_hosts = {h for h in all_hosts if self.is_in_scope(h, target)}
        
        # Write all.txt
        all_file = os.path.join(output_dir, 'all.txt')
        self.write_clean_results(all_hosts, all_file)
        self.log(f"Unique hosts found: {len(all_hosts)}", "INFO", Colors.GREEN)
        
        # Step 7: httpx
        step = 7
        result = ToolResult(tool_name='httpx')
        
        self.log(f"Starting httpx to identify live hosts...", "INFO", Colors.CYAN)
        self.update_status_display(step, total_steps, 'HTTPX', result)
        
        # Write all hosts to temp file for httpx
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        for host in sorted(all_hosts):
            temp_file.write(f"{host}\n")
        temp_file.close()
        
        # Build httpx command
        timeout_seconds = time_minutes * 60
        cmd = self.build_httpx_command(temp_file.name, threads, time_minutes)
        httpx_result = self.run_tool('httpx', cmd, timeout_seconds=timeout_seconds)
        
        live_urls = set()
        if httpx_result.raw_output:
            # httpx outputs URLs directly
            for line in httpx_result.raw_output.splitlines():
                line = line.strip()
                if line:
                    try:
                        parsed = urllib.parse.urlparse(line)
                        if parsed.scheme in ['http', 'https'] and parsed.hostname:
                            if self.is_in_scope(parsed.hostname, target):
                                live_urls.add(line)
                    except:
                        pass
        
        result.results = self.filter_live_urls(live_urls, target)
        live_file = os.path.join(output_dir, 'live.txt')
        self.write_clean_results(result.results, live_file)
        
        # Store the result
        result.raw_output = httpx_result.raw_output
        result.stderr = httpx_result.stderr
        result.elapsed_time = httpx_result.elapsed_time
        result.status = httpx_result.status
        result.timed_out = httpx_result.timed_out
        result.exit_code = httpx_result.exit_code
        
        tool_results['httpx'] = result
        self.update_status_display(step, total_steps, 'HTTPX', result)
        self.log(f"Live hosts found: {len(result.results)}", "INFO", Colors.GREEN)
        
        # Clean up temp file
        try:
            os.unlink(temp_file.name)
        except:
            pass
        
        # Step 8: Gowitness
        step = 8
        result = ToolResult(tool_name='Gowitness')
        
        if len(live_urls) > 0:
            self.log(f"Starting Gowitness to capture screenshots...", "INFO", Colors.CYAN)
            self.update_status_display(step, total_steps, 'GOWITNESS', result)
            
            # Use live.txt as input
            cmd = self.build_gowitness_command(live_file, threads)
            # NO TIMEOUT for Gowitness - runs naturally
            gowitness_result = self.run_tool('Gowitness', cmd, timeout_seconds=None)
            
            result.status = gowitness_result.status
            result.elapsed_time = gowitness_result.elapsed_time
            result.exit_code = gowitness_result.exit_code
            result.stderr = gowitness_result.stderr
            
            tool_results['Gowitness'] = result
            self.update_status_display(step, total_steps, 'GOWITNESS', result)
            self.log(f"Screenshots captured: {len(live_urls)}", "INFO", Colors.GREEN)
        else:
            result.status = "skipped"
            tool_results['Gowitness'] = result
            self.update_status_display(step, total_steps, 'GOWITNESS', result)
            self.log("Gowitness skipped - no live URLs found", "INFO", Colors.YELLOW)
        
        # Write individual tool files if in 'all' mode
        if output_mode == 'all':
            for tool_name, tool_result in tool_results.items():
                if tool_name in ['Amass', 'Subfinder', 'Assetfinder', 'Sublist3r', 'dnscan']:
                    filename = os.path.join(output_dir, f"{tool_name.lower()}.txt")
                    self.write_clean_results(tool_result.results, filename)
            
            # Write logs
            logs_dir = os.path.join(output_dir, 'logs')
            for tool_name, tool_result in tool_results.items():
                if tool_result.raw_output:
                    log_file = os.path.join(logs_dir, f"{tool_name.lower()}.log")
                    with open(log_file, 'w') as f:
                        f.write(tool_result.raw_output)
                        if tool_result.stderr:
                            f.write("\n\n--- STDERR ---\n")
                            f.write(tool_result.stderr)
        
        # Display final summary
        self.display_summary(target, output_dir, all_hosts, live_urls, tool_results)

    def display_summary(self, target: str, output_dir: str, all_hosts: Set[str], 
                        live_urls: Set[str], tool_results: Dict[str, ToolResult]):
        """Display the final summary"""
        summary = f"""
{Colors.BOLD}{Colors.CYAN}============================================
                    SIATK SUMMARY
============================================{Colors.RESET}

{Colors.BOLD}Target:{Colors.RESET} {target}

"""
        # Tool results
        for tool_name in ['Amass', 'Subfinder', 'Assetfinder', 'Sublist3r', 'dnscan']:
            if tool_name in tool_results:
                result = tool_results[tool_name]
                count = len(result.results)
                status = result.status
                status_color = Colors.GREEN if status == 'done' else Colors.YELLOW if status == 'timeout' else Colors.RED
                summary += f"{Colors.BOLD}{tool_name}:{Colors.RESET} {status_color}{count:>6}{Colors.RESET} ({status})\n"
        
        summary += f"""
{Colors.BOLD}Unique hosts:{Colors.RESET} {Colors.GREEN}{len(all_hosts):>6}{Colors.RESET}
{Colors.BOLD}Live hosts:{Colors.RESET}   {Colors.GREEN}{len(live_urls):>6}{Colors.RESET}
{Colors.BOLD}Screenshots:{Colors.RESET}  {Colors.GREEN}{len(live_urls):>6}{Colors.RESET}

{Colors.BOLD}Output:{Colors.RESET}
    {output_dir}

{Colors.BOLD}Status:{Colors.RESET} {Colors.GREEN}COMPLETED{Colors.RESET}
{Colors.CYAN}============================================{Colors.RESET}
"""
        print(summary)

    def main(self):
        """Main entry point"""
        # Parse arguments
        parser = argparse.ArgumentParser(
            description='SIATK - Subdomain Intelligence & Asset Toolkit',
            add_help=False
        )
        parser.add_argument('-u', '--url', help='Target root domain')
        parser.add_argument('-w', '--wordlist', help='Wordlist for dnscan only')
        parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
        parser.add_argument('-o', '--output', choices=['combined', 'all'], default='combined', 
                           help='Output mode: combined or all')
        parser.add_argument('--time-minutes', type=int, default=10, help='Maximum runtime in minutes')
        parser.add_argument('-h', '--help', action='store_true', help='Show help message')
        
        try:
            args = parser.parse_args()
        except SystemExit:
            self.print_help()
            return 0
        
        if args.help:
            self.print_help()
            return 0
            
        if not args.url:
            self.log("Error: Target URL (-u) is required", "ERROR", Colors.RED)
            self.print_help()
            return 1
        
        # Validate arguments
        if args.threads < 1:
            self.log("Error: Threads must be >= 1", "ERROR", Colors.RED)
            return 1
            
        if args.time_minutes < 1:
            self.log("Error: Time-minutes must be >= 1", "ERROR", Colors.RED)
            return 1
        
        # Normalize target
        target = self.normalize_target(args.url)
        
        if not self.validate_target(target):
            self.log(f"Error: Invalid target domain: {target}", "ERROR", Colors.RED)
            return 1
            
        # Validate wordlist if provided
        if args.wordlist:
            if not os.path.exists(args.wordlist):
                self.log(f"Error: Wordlist file not found: {args.wordlist}", "ERROR", Colors.RED)
                return 1
            if not os.access(args.wordlist, os.R_OK):
                self.log(f"Error: Wordlist file not readable: {args.wordlist}", "ERROR", Colors.RED)
                return 1
        
        # Preflight check for required tools
        if not self.preflight_check():
            return 1
            
        # Setup configuration
        self.config.target = target
        self.config.wordlist = args.wordlist
        self.config.threads = args.threads
        self.config.output_mode = args.output
        self.config.time_minutes = args.time_minutes
        
        # Create output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.config.timestamp = timestamp
        output_dir_name = f"{target}_{timestamp}"
        self.config.output_dir = os.path.join('output', output_dir_name)
        
        try:
            # Run the pipeline
            self.run_pipeline()
        except KeyboardInterrupt:
            self.log("\nInterrupted by user. Cleaning up...", "WARNING", Colors.YELLOW)
            # Kill all running processes
            for process in self.running_processes:
                self.kill_process_group(process)
            self.log("Cleanup complete.", "INFO", Colors.GREEN)
            return 130
        except Exception as e:
            self.log(f"Unexpected error: {str(e)}", "ERROR", Colors.RED)
            return 1
            
        return 0

def main():
    """Entry point"""
    app = SIATK()
    try:
        sys.exit(app.main())
    except KeyboardInterrupt:
        sys.exit(130)

if __name__ == "__main__":
    main()
