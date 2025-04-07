#!/usr/bin/env python3
"""
Enhanced VirusTotal IOC Scanner with HTML Report Generation

A streamlined tool to scan IOCs against VirusTotal API with a static HTML report,
improved visualizations, optimized for Premium API usage, and enhanced safety measures.
"""

import base64
import csv
import getpass
import json
import logging
import os
import re
import sys
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union
from urllib.parse import urlparse

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
    import pandas as pd
    from tqdm import tqdm
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--trusted-host", "pypi.org", 
                           "--trusted-host", "files.pythonhosted.org", "requests", "tqdm", "pandas"])
    import requests
    import pandas as pd
    from tqdm import tqdm

# Import report generator
from report_generator import generate_html_report

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("vt_scanner.log"), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Console colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"

def save_api_key(api_key: str) -> None:
    """Save API key to config file with proper permissions"""
    config_dir = Path.home() / ".vtscanner"
    config_file = config_dir / "config.json"
    config_dir.mkdir(exist_ok=True)
    try:
        with open(config_file, 'w') as f:
            json.dump({"api_key": api_key}, f)
        # Set secure permissions
        os.chmod(config_file, 0o600)
        print(f"{GREEN}API key saved securely.{RESET}")
    except Exception as e:
        print(f"{RED}Error saving API key: {str(e)}{RESET}")


def load_api_key() -> Optional[str]:
    """Load API key from config file"""
    config_file = Path.home() / ".vtscanner" / "config.json"
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                return json.load(f).get("api_key")
        except Exception as e:
            print(f"{RED}Error loading API key: {str(e)}{RESET}")
    return None


def sanitize_ioc(ioc: str) -> str:
    """Sanitize IOC to prevent any accidental execution or code injection"""
    if not isinstance(ioc, str):
        return str(ioc)
    
    # Remove any control characters and strip whitespace
    ioc = re.sub(r'[\x00-\x1f\x7f]', '', ioc).strip()
    
    # Escape HTML special characters
    ioc = ioc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    ioc = ioc.replace('"', '&quot;').replace("'", '&#x27;')
    
    return ioc


class IOCScanner:
    def __init__(self, api_key: str, max_workers: int = 10, scan_mode: str = 'premium'):
        self.api_key = api_key
        self.max_workers = max_workers
        self.scan_mode = scan_mode
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "User-Agent": "IOCScanner/5.0 (Premium)"})
        self.session.verify = False  # Disable SSL verification by default
        self.base_url = "https://www.virustotal.com/api/v3"
        self.total_iocs = 0
        self.malicious_count = 0
        self.suspicious_count = 0
        self.error_count = 0
        self.processed_iocs = set()
        self.last_request_time = 0
        self.scan_start_time = time.time()
        self.ioc_types = {}
        self.total_engines = 0
        self.critical_count = 0
        self.dataframe = None
        self.results_list = []

    def identify_ioc_type(self, ioc: str) -> str:
        """Identify the type of IOC (ip, domain, url, hash, email)"""
        if not isinstance(ioc, str) or not ioc.strip():
            return "unknown"
        
        ioc = ioc.strip().strip('"\'')
        
        # IP address
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ioc):
            try:
                if all(0 <= int(p) <= 255 for p in ioc.split('.')):
                    return "ip"
            except ValueError:
                pass
        
        # Email address
        if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", ioc):
            return "email"
        
        # Domain
        if re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", ioc):
            return "domain"
        
        # URL
        if re.match(r"^https?://", ioc) or ioc.startswith("www.") or ("/" in ioc and "." in ioc):
            return "url"
        
        # Hash (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
            return "hash"
        
        return "unknown"

    def print_detection_bar(self, positives: int, total: int) -> None:
        """Print a visual detection bar in the console"""
        if total == 0:
            return
            
        ratio = positives / total
        width = 30  # width of the bar
        filled_width = int(width * ratio)
        
        if ratio > 0.5:
            color = RED
            severity = f"{BG_RED}{BOLD} CRITICAL {RESET}"
        elif ratio > 0.25:
            color = YELLOW
            severity = f"{BG_YELLOW}{BOLD} HIGH {RESET}"
        elif ratio > 0:
            color = BLUE
            severity = f"{BLUE}{BOLD} MEDIUM {RESET}"
        else:
            color = GREEN
            severity = f"{BG_GREEN}{BOLD} CLEAN {RESET}"
            
        bar = f"{color}{'█' * filled_width}{RESET}{'░' * (width - filled_width)}"
        percentage = f"{ratio:.1%}"
        
        print(f"  Detection: {bar} {percentage} {severity}")

    def check_ioc(self, ioc: str, ioc_type: Optional[str] = None) -> Dict:
        """Check an IOC against VirusTotal API with optimization for Premium API"""
        if not isinstance(ioc, str):
            return {"ioc": str(ioc), "ioc_type": "unknown", "error": "Invalid IOC format"}
            
        # Sanitize the IOC to prevent any execution or injection
        original_ioc = ioc
        ioc = sanitize_ioc(ioc.strip().strip("'\""))
        
        if not ioc or ioc in self.processed_iocs:
            return {"ioc": ioc, "ioc_type": "unknown", "error": "Empty or duplicate IOC"}
        
        self.processed_iocs.add(ioc)
        self.total_iocs += 1

        if not ioc_type or ioc_type == "unknown":
            ioc_type = self.identify_ioc_type(ioc)
            
        # Track IOC types distribution
        self.ioc_types[ioc_type] = self.ioc_types.get(ioc_type, 0) + 1
        
        if ioc_type == "unknown":
            self.error_count += 1
            return {"ioc": ioc, "ioc_type": "unknown", "error": "Unknown IOC type", "vt_link": ""}
            
        # Skip email scanning directly as it's not supported by VirusTotal API
        if ioc_type == "email":
            # For emails, we'll handle domain part separately
            domain_part = ioc.split('@')[-1]
            if domain_part:
                print(f"\n{YELLOW}Email detected: {ioc}, checking domain part: {domain_part}{RESET}")
                domain_result = self.check_ioc(domain_part, "domain")
                # Add the email result but mark it properly
                email_result = {
                    "ioc": original_ioc,
                    "ioc_type": "email",
                    "email_domain": domain_part,
                    "vt_link": domain_result.get("vt_link", ""),
                    "vt_positives": domain_result.get("vt_positives", 0),
                    "vt_total": domain_result.get("vt_total", 0),
                    "vt_detection_ratio": domain_result.get("vt_detection_ratio", "0/0"),
                    "vt_detection_percentage": domain_result.get("vt_detection_percentage", 0),
                    "vt_malicious": domain_result.get("vt_malicious", 0),
                    "vt_suspicious": domain_result.get("vt_suspicious", 0),
                    "vt_harmless": domain_result.get("vt_harmless", 0),
                    "vt_undetected": domain_result.get("vt_undetected", 0),
                    "vt_last_analysis_date": domain_result.get("vt_last_analysis_date", ""),
                    "category": f"Email Domain: {domain_result.get('category', '')}",
                    "detection_names": domain_result.get("detection_names", ""),
                    "error": ""
                }
                return email_result
            else:
                self.error_count += 1
                return {"ioc": ioc, "ioc_type": "email", "error": "Invalid email format", "vt_link": ""}

        # Premium API has higher rate limits, but we'll still implement a minimal delay
        # between requests to prevent overwhelming the API
        if self.scan_mode == "premium":
            elapsed = time.time() - self.last_request_time
            if elapsed < 0.5 and self.last_request_time > 0:  # 0.5 seconds between requests
                time.sleep(0.5 - elapsed)
        else:
            # Standard API rate limiting
            elapsed = time.time() - self.last_request_time
            if elapsed < 15 and self.last_request_time > 0:
                time.sleep(15 - elapsed)
                
        self.last_request_time = time.time()

        # Set up the appropriate endpoint and link
        endpoint = ""
        vt_link = ""
        
        if ioc_type == "ip":
            endpoint = f"{self.base_url}/ip_addresses/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/ip-address/{ioc}"
        elif ioc_type == "domain":
            endpoint = f"{self.base_url}/domains/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/domain/{ioc}"
        elif ioc_type == "url":
            if ioc.startswith("www."):
                ioc = "http://" + ioc
            try:
                encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                endpoint = f"{self.base_url}/urls/{encoded_url}"
                vt_link = f"https://www.virustotal.com/gui/url/{encoded_url}"
            except Exception as e:
                self.error_count += 1
                return {"ioc": ioc, "ioc_type": ioc_type, "error": f"URL encoding error: {str(e)}", "vt_link": ""}
        elif ioc_type == "hash":
            endpoint = f"{self.base_url}/files/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/file/{ioc}"

        # Make the API request with retries
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.get(endpoint, timeout=30)
                
                if response.status_code == 429:
                    print(f"{YELLOW}Rate limited. Waiting 60 seconds...{RESET}")
                    time.sleep(60)
                    continue
                    
                response.raise_for_status()
                result = response.json()

                # Parse the response
                data = result.get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = sum(stats.values()) or 1  # Avoid division by zero
                
                # Keep track of average engines count for reporting
                if self.total_engines == 0:
                    self.total_engines = total
                else:
                    self.total_engines = (self.total_engines + total) / 2
                
                detection_percentage = ((malicious + suspicious) / total) * 100
                detection_ratio = f"{malicious + suspicious}/{total}"
                
                # Get last analysis date
                last_analysis_date = (
                    datetime.fromtimestamp(attributes["last_analysis_date"]).strftime('%Y-%m-%d %H:%M:%S')
                    if attributes.get("last_analysis_date") else ""
                )
                
                # Get category/type details for domains and IPs
                category = ""
                if ioc_type == "domain" or ioc_type == "ip":
                    category = attributes.get("categories", {}).get("Webroot", "")
                    
                    if not category and attributes.get("category"):
                        category = attributes.get("category")
                
                # Get more details for files
                file_type = ""
                file_size = ""
                if ioc_type == "hash":
                    file_type = attributes.get("type_description", "")
                    file_size = attributes.get("size", 0)
                    
                # Get detection names for malicious/suspicious indicators
                detection_names = []
                if malicious + suspicious > 0 and "last_analysis_results" in attributes:
                    results = attributes["last_analysis_results"]
                    for engine, engine_result in results.items():
                        if engine_result.get("category") in ["malicious", "suspicious"]:
                            detection_name = engine_result.get("result", "")
                            if detection_name:
                                detection_names.append(f"{engine}: {detection_name}")

                if malicious + suspicious > 0:
                    if malicious > 0:
                        self.malicious_count += 1
                    else:
                        self.suspicious_count += 1
                        
                    # Count critical findings
                    if (malicious + suspicious) / total > 0.5:
                        self.critical_count += 1
                
                # Build enhanced result object
                result = {
                    "ioc": original_ioc,  # Use original for display
                    "ioc_type": ioc_type,
                    "vt_positives": malicious + suspicious,
                    "vt_total": total,
                    "vt_detection_ratio": detection_ratio,
                    "vt_detection_percentage": detection_percentage,
                    "vt_malicious": malicious,
                    "vt_suspicious": suspicious,
                    "vt_harmless": harmless,
                    "vt_undetected": undetected,
                    "vt_link": vt_link,
                    "vt_last_analysis_date": last_analysis_date,
                    "category": category,
                    "file_type": file_type,
                    "file_size": file_size,
                    "detection_names": "; ".join(detection_names[:5]),  # Limit to top 5
                    "error": ""
                }
                
                # Print detection information for malicious IOCs
                if malicious + suspicious > 0:
                    if ioc_type == "url" or ioc_type == "domain":
                        # Mask the actual URL/domain in terminal output for safety
                        masked_ioc = original_ioc[:5] + "*****" + original_ioc[-5:] if len(original_ioc) > 10 else original_ioc
                        print(f"\n{BOLD}{masked_ioc}{RESET} ({ioc_type}):")
                    else:
                        print(f"\n{BOLD}{original_ioc}{RESET} ({ioc_type}):")
                    
                    self.print_detection_bar(malicious + suspicious, total)
                
                return result
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1 and not str(e).startswith("404"):
                    print(f"{YELLOW}Attempt {attempt+1} failed: {str(e)}. Retrying...{RESET}")
                    time.sleep(5)
                else:
                    self.error_count += 1
                    error_message = str(e)
                    if "404" in error_message:
                        error_message = "Not found in VirusTotal database"
                    
                    return {
                        "ioc": original_ioc, 
                        "ioc_type": ioc_type, 
                        "error": f"API error: {error_message}", 
                        "vt_link": vt_link,
                        "vt_positives": 0,
                        "vt_total": 0,
                        "vt_detection_ratio": "0/0",
                        "vt_detection_percentage": 0
                    }

    def process_file(self, file_path: str, output_path: str = None) -> List[Dict]:
        """Process a file containing IOCs with premium API optimizations"""
        file_path = Path(file_path)
        
        # Determine output path for CSV export
        if not output_path:
            # Use the directory of the script file
            script_dir = Path(sys.argv[0]).resolve().parent
            output_name = f"{file_path.stem}_vt_report.csv"
            output_path = script_dir / output_name
        else:
            output_path = Path(output_path)

        # Parse the file containing IOCs
        iocs = []
        try:
            # Try to determine file type by extension
            file_ext = file_path.suffix.lower()
            
            if file_ext in ['.xlsx', '.xls']:
                # Excel file
                try:
                    import pandas as pd
                    df = pd.read_excel(file_path)
                    # Look for columns that might contain IOCs
                    potential_ioc_cols = []
                    for col in df.columns:
                        if any(kw in col.lower() for kw in ['ioc', 'indicator', 'ip', 'domain', 'url', 'hash', 'md5', 'sha', 'email']):
                            potential_ioc_cols.append(col)
                    
                    # If no obvious IOC columns, use all columns
                    if not potential_ioc_cols:
                        potential_ioc_cols = df.columns
                    
                    # Extract IOCs from the dataframe
                    for col in potential_ioc_cols:
                        for value in df[col].dropna():
                            value = str(value).strip()
                            if value and not value.startswith('#'):
                                ioc_type = self.identify_ioc_type(value)
                                iocs.append({"ioc": value, "ioc_type": ioc_type})
                except Exception as e:
                    print(f"{RED}Error reading Excel file: {str(e)}{RESET}")
            else:
                # Treat as text file (CSV, TXT, etc.)
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ioc_type = self.identify_ioc_type(line)
                            iocs.append({"ioc": line, "ioc_type": ioc_type})
        except Exception as e:
            print(f"{RED}Error reading file: {str(e)}{RESET}")
            return []

        if not iocs:
            print(f"{RED}No valid IOCs found in file.{RESET}")
            return []

        print(f"{BLUE}Found {len(iocs)} IOCs to check.{RESET}")
        
        # Count IOCs by type
        ioc_types = {}
        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "unknown")
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
        print(f"\n{BOLD}IOC Types:{RESET}")
        for ioc_type, count in sorted(ioc_types.items()):
            print(f"  {ioc_type}: {count}")

        # Process the IOCs in parallel with a progress bar - use more workers for Premium API
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.check_ioc, ioc["ioc"], ioc.get("ioc_type")): ioc for ioc in iocs}
            
            with tqdm(total=len(iocs), desc="Checking IOCs") as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    pbar.update(1)
                    pbar.set_description(f"Checking IOCs (Malicious: {self.malicious_count}/{self.total_iocs})")

        self.results_list = results
        
        # Calculate scan duration
        scan_duration = time.time() - self.scan_start_time
        scan_duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
        
        # Convert to DataFrame for easier processing
        try:
            self.dataframe = pd.DataFrame(results)
            
            # Ensure vt_detection_percentage is numeric
            if 'vt_detection_percentage' in self.dataframe.columns:
                self.dataframe['vt_detection_percentage'] = pd.to_numeric(
                    self.dataframe['vt_detection_percentage'], errors='coerce')
        except Exception as e:
            print(f"{RED}Error creating DataFrame: {str(e)}{RESET}")
        
        # Export results to CSV
        if hasattr(self, 'dataframe') and self.dataframe is not None and not self.dataframe.empty:
            try:
                self.dataframe.to_csv(output_path, index=False)
                print(f"\n{GREEN}Results exported to CSV: {output_path}{RESET}")
            except Exception as e:
                print(f"{RED}Error exporting to CSV: {str(e)}{RESET}")
        
        # Print summary
        clean_count = self.total_iocs - self.malicious_count - self.suspicious_count - self.error_count
        
        print(f"\n{BOLD}Scan Summary:{RESET}")
        print(f"Total IOCs checked: {self.total_iocs}")
        print(f"Malicious IOCs: {self.malicious_count}")
        print(f"Suspicious IOCs: {self.suspicious_count}")
        print(f"Clean IOCs: {clean_count}")
        print(f"Errors: {self.error_count}")
        print(f"Scan duration: {scan_duration_str}")
        
        if self.malicious_count > 0:
            print(f"\n{RED}{BOLD}⚠️ IMPORTANT: {self.critical_count} critical threats detected!{RESET}")
            
        return results
    
    def generate_html_report(self, input_filename: str, output_path: str = None) -> str:
        """Generate an HTML report from the scan results"""
        if not self.results_list:
            print(f"{RED}No results to display.{RESET}")
            return None
        
        # Prepare scan stats dictionary for the report
        scan_stats = {
            'total_iocs': self.total_iocs,
            'malicious_count': self.malicious_count,
            'suspicious_count': self.suspicious_count,
            'error_count': self.error_count,
            'critical_count': self.critical_count,
            'scan_start_time': self.scan_start_time,
            'total_engines': self.total_engines
        }
        
        # Generate HTML report using the imported function
        report_path = generate_html_report(
            self.results_list, 
            scan_stats, 
            output_path=output_path, 
            input_filename=input_filename
        )
        
        return report_path


class BatchIOCScanner:
    """
    A class for processing IOCs in batch mode for Premium API usage efficiency
    Optimized for higher throughput with the Premium API
    """
    
    def __init__(self, api_key: str, batch_size: int = 100):
        self.api_key = api_key
        self.batch_size = batch_size
        self.session = requests.Session()
        self.session.headers.update({"x-apikey": api_key, "User-Agent": "BatchIOCScanner/1.0 (Premium)"})
        self.session.verify = False
        self.base_url = "https://www.virustotal.com/api/v3"
        
    def batch_process_hashes(self, hashes: List[str]) -> Dict:
        """Process a batch of file hashes using Premium API's batch endpoint"""
        if not hashes:
            return {}
        
        url = f"{self.base_url}/files"
        data = {"data": {"hashes": hashes}}
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error in batch processing: {str(e)}{RESET}")
            return {}
    
    def batch_process_urls(self, urls: List[str]) -> Dict:
        """Process a batch of URLs using Premium API's batch endpoint"""
        if not urls:
            return {}
        
        # Encode URLs
        encoded_urls = []
        for url in urls:
            try:
                if url.startswith("www."):
                    url = "http://" + url
                encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                encoded_urls.append(encoded_url)
            except Exception as e:
                print(f"{RED}Error encoding URL {url}: {str(e)}{RESET}")
                
        if not encoded_urls:
            return {}
            
        url = f"{self.base_url}/urls/batch"
        data = {"data": {"urls": encoded_urls}}
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"{RED}Error in batch processing: {str(e)}{RESET}")
            return {}
            
    def batch_process_ips(self, ips: List[str]) -> Dict:
        """Process a batch of IPs using Premium API endpoint"""
        # Note: VT API doesn't have a batch endpoint for IPs, but we can use multiple requests with higher rate limits
        results = {}
        for ip in ips:
            try:
                url = f"{self.base_url}/ip_addresses/{ip}"
                response = self.session.get(url)
                response.raise_for_status()
                results[ip] = response.json()
            except requests.exceptions.RequestException as e:
                print(f"{YELLOW}Error processing IP {ip}: {str(e)}{RESET}")
                results[ip] = {"error": str(e)}
        return results
    
    def batch_process_domains(self, domains: List[str]) -> Dict:
        """Process a batch of domains using Premium API endpoint"""
        # Note: VT API doesn't have a batch endpoint for domains, but we can use multiple requests with higher rate limits
        results = {}
        for domain in domains:
            try:
                url = f"{self.base_url}/domains/{domain}"
                response = self.session.get(url)
                response.raise_for_status()
                results[domain] = response.json()
            except requests.exceptions.RequestException as e:
                print(f"{YELLOW}Error processing domain {domain}: {str(e)}{RESET}")
                results[domain] = {"error": str(e)}
        return results


def main():
    """Main function"""
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}Enhanced VirusTotal IOC Scanner (Premium Version){RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"\n{BLUE}This tool uses the Premium VirusTotal API for high-throughput scanning.{RESET}")
    print(f"{YELLOW}Features static HTML report generation and enhanced visualizations.{RESET}")
    
    # Get API key
    api_key = load_api_key() or os.environ.get("VT_API_KEY")
    if api_key:
        if input(f"\n{BOLD}Use saved API key? (Y/n): {RESET}").lower() == 'n':
            api_key = getpass.getpass(f"{BOLD}Enter your VirusTotal Premium API key: {RESET}")
    else:
        print(f"\n{YELLOW}No saved API key found.{RESET}")
        api_key = getpass.getpass(f"{BOLD}Enter your VirusTotal Premium API key: {RESET}")

    if not api_key:
        print(f"{RED}Error: No API key provided. Exiting.{RESET}")
        sys.exit(1)

    if not load_api_key() and input(f"{BOLD}Save this API key? (Y/n): {RESET}").lower() != 'n':
        save_api_key(api_key)
        print(f"{GREEN}API key saved successfully.{RESET}")

    # Get input file
    input_file = ""
    while not input_file or not os.path.exists(input_file):
        input_file = input(f"\n{BOLD}Enter the path to your IOC file: {RESET}")
        if not input_file:
            print(f"{RED}Please enter a valid file path.{RESET}")
        elif not os.path.exists(input_file):
            print(f"{RED}File not found: {input_file}{RESET}")

    # Get output file for CSV
    csv_output_file = input(f"\n{BOLD}Enter output CSV file path (Enter for default): {RESET}")
    
    # Get output file for HTML report
    html_output_file = input(f"\n{BOLD}Enter output HTML file path (Enter for default): {RESET}")
    
    # Worker configuration
    max_workers = 10  # Default for Premium API
    try:
        worker_input = input(f"\n{BOLD}Enter max number of parallel workers (default: 10): {RESET}")
        if worker_input.strip():
            max_workers = int(worker_input)
            if max_workers < 1:
                max_workers = 1
            elif max_workers > 20:
                print(f"{YELLOW}Large number of workers may lead to unstable performance. Capping at 20.{RESET}")
                max_workers = 20
    except ValueError:
        print(f"{YELLOW}Invalid input. Using default value of 10 workers.{RESET}")
    
    print(f"\n{BLUE}Starting scan with {max_workers} worker{'' if max_workers == 1 else 's'}...{RESET}")
    
    # Initialize scanner and process file
    scanner = IOCScanner(api_key, max_workers=max_workers, scan_mode="premium")
    results = scanner.process_file(input_file, csv_output_file)
    
    # Generate HTML report if there are results
    if results:
        html_path = scanner.generate_html_report(input_file, html_output_file)
        if html_path:
            print(f"\n{GREEN}HTML report generated: {html_path}{RESET}")
    
    print(f"\n{GREEN}Thank you for using the Enhanced VirusTotal IOC Scanner!{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Process interrupted by user. Exiting.{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}An unexpected error occurred: {str(e)}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
