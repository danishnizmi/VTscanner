#!/usr/bin/env python3
"""
VirusTotal IOC Scanner with HTML Report Generator

A streamlined tool to scan Indicators of Compromise (IOCs) against VirusTotal API,
with an interactive HTML report for visualizing results, optimized for both Standard
and Premium API usage.

Authors: VT Scanner Team
Version: 1.1.0
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
from typing import Dict, List, Optional, Tuple, Any, Union, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("vt_scanner.log", mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Terminal colors for better user experience
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

# Try importing required dependencies
try:
    import requests
    import pandas as pd
    from tqdm import tqdm
    
    # Check for report_generator
    report_generator_path = Path(__file__).parent / "report_generator.py"
    if not report_generator_path.exists():
        print(f"{RED}Error: report_generator.py is missing in {Path(__file__).parent}{RESET}")
        print(f"{YELLOW}Please make sure report_generator.py is in the same directory.{RESET}")
        sys.exit(1)
        
    # Import report generator module
    try:
        from report_generator import generate_html_report
    except ImportError as e:
        print(f"{RED}Error importing report_generator module: {e}{RESET}")
        sys.exit(1)
        
    # Suppress SSL warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass  # Continue without suppressing warnings if urllib3 is not available
        
except ImportError as e:
    missing_package = str(e).split("'")[1] if "'" in str(e) else str(e)
    print(f"{RED}Error: Missing required package: {missing_package}{RESET}")
    print(f"{YELLOW}Please install required packages using pip install:{RESET}")
    print("  pip install requests pandas tqdm plotly")
    sys.exit(1)


class APIKeyManager:
    """Manages VirusTotal API key storage and retrieval."""
    
    @staticmethod
    def save(api_key: str) -> bool:
        """
        Save API key to a secure config file.
        
        Args:
            api_key: The VirusTotal API key to save
            
        Returns:
            bool: True if successfully saved, False otherwise
        """
        config_dir = Path.home() / ".vtscanner"
        config_file = config_dir / "config.json"
        config_dir.mkdir(exist_ok=True)
        
        try:
            with open(config_file, 'w') as f:
                json.dump({"api_key": api_key}, f)
                
            # Set secure permissions (Unix-like systems)
            try:
                os.chmod(config_file, 0o600)
            except Exception:
                # Windows or other systems where chmod may not work
                pass
                
            return True
        except Exception as e:
            logger.error(f"Error saving API key: {e}")
            return False

    @staticmethod
    def load() -> Optional[str]:
        """
        Load API key from config file.
        
        Returns:
            str or None: The API key if found, None otherwise
        """
        config_file = Path.home() / ".vtscanner" / "config.json"
        
        if not config_file.exists():
            return None
            
        try:
            with open(config_file, 'r') as f:
                return json.load(f).get("api_key")
        except Exception as e:
            logger.error(f"Error loading API key: {e}")
            return None


class IOCHelper:
    """Helper class for IOC-related operations."""
    
    @staticmethod
    def sanitize(ioc: str) -> str:
        """
        Sanitize IOC to prevent any accidental execution or code injection.
        
        Args:
            ioc: The IOC string to sanitize
            
        Returns:
            A sanitized version of the IOC
        """
        if not isinstance(ioc, str):
            return str(ioc)
        
        # Remove any control characters and strip whitespace
        ioc = re.sub(r'[\x00-\x1f\x7f]', '', ioc).strip()
        
        # Escape HTML special characters
        ioc = ioc.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        ioc = ioc.replace('"', '&quot;').replace("'", '&#x27;')
        
        return ioc

    @staticmethod
    def identify_type(ioc: str) -> str:
        """
        Identify the type of IOC (ip, domain, url, hash, email).
        
        Args:
            ioc: The IOC string to identify
            
        Returns:
            The identified type as a string
        """
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


class VirusTotalScanner:
    """
    Main class for scanning IOCs against VirusTotal API.
    Supports both Premium and Standard API usage patterns.
    """
    
    def __init__(self, api_key: str, max_workers: int = 10, scan_mode: str = 'premium'):
        """
        Initialize the scanner.
        
        Args:
            api_key: VirusTotal API key
            max_workers: Maximum number of concurrent workers for threading
            scan_mode: 'premium' or 'standard' for API rate limiting
        """
        self.api_key = api_key
        self.max_workers = max(1, min(max_workers, 20))  # Clamp between 1 and 20
        self.scan_mode = scan_mode
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "User-Agent": f"VTScanner/1.1.0 ({scan_mode})"
        })
        self.session.verify = False  # Disable SSL verification
        self.base_url = "https://www.virustotal.com/api/v3"
        
        # Tracking variables
        self.total_iocs: int = 0
        self.malicious_count: int = 0
        self.suspicious_count: int = 0
        self.error_count: int = 0
        self.processed_iocs: Set[str] = set()
        self.last_request_time: float = 0
        self.scan_start_time: float = time.time()
        self.ioc_types: Dict[str, int] = {}
        self.total_engines: float = 0
        self.critical_count: int = 0
        self.results_list: List[Dict] = []

    def print_detection_bar(self, positives: int, total: int) -> None:
        """
        Print a visual detection bar in the console.
        
        Args:
            positives: Number of positive detections
            total: Total number of engines
        """
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
        """
        Check an IOC against VirusTotal API.
        
        Args:
            ioc: The IOC to check
            ioc_type: Optional type if already known
            
        Returns:
            Dict: Result dictionary with detection information
        """
        if not isinstance(ioc, str):
            return {"ioc": str(ioc), "ioc_type": "unknown", "error": "Invalid IOC format"}
            
        # Sanitize the IOC to prevent any execution or injection
        original_ioc = ioc
        ioc = IOCHelper.sanitize(ioc.strip().strip("'\""))
        
        if not ioc or ioc in self.processed_iocs:
            return {"ioc": ioc, "ioc_type": "unknown", "error": "Empty or duplicate IOC"}
        
        self.processed_iocs.add(ioc)
        self.total_iocs += 1

        if not ioc_type or ioc_type == "unknown":
            ioc_type = IOCHelper.identify_type(ioc)
            
        # Track IOC types distribution
        self.ioc_types[ioc_type] = self.ioc_types.get(ioc_type, 0) + 1
        
        if ioc_type == "unknown":
            self.error_count += 1
            return {"ioc": ioc, "ioc_type": "unknown", "error": "Unknown IOC type", "vt_link": ""}
            
        # Special handling for email IOCs (not directly supported by VT API)
        if ioc_type == "email":
            return self._handle_email_ioc(original_ioc, ioc)

        # Apply rate limiting based on API mode
        self._apply_rate_limiting()
                
        # Set up the appropriate endpoint and link
        endpoint, vt_link = self._get_endpoint_and_link(ioc, ioc_type)
        if not endpoint:
            self.error_count += 1
            return {
                "ioc": ioc, 
                "ioc_type": ioc_type, 
                "error": "Failed to create API endpoint", 
                "vt_link": ""
            }

        # Make the API request with retries
        return self._make_api_request(endpoint, vt_link, original_ioc, ioc_type)

    def _handle_email_ioc(self, original_ioc: str, ioc: str) -> Dict:
        """Handle email IOCs by checking the domain part."""
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

    def _apply_rate_limiting(self) -> None:
        """Apply appropriate rate limiting based on API mode."""
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

    def _get_endpoint_and_link(self, ioc: str, ioc_type: str) -> Tuple[str, str]:
        """Generate API endpoint and link for the specified IOC."""
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
                logger.error(f"URL encoding error: {e}")
                return "", ""
        elif ioc_type == "hash":
            endpoint = f"{self.base_url}/files/{ioc}"
            vt_link = f"https://www.virustotal.com/gui/file/{ioc}"
            
        return endpoint, vt_link

    def _make_api_request(self, endpoint: str, vt_link: str, original_ioc: str, ioc_type: str) -> Dict:
        """Make API request with error handling and retries."""
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
                return self._parse_vt_response(result, original_ioc, ioc_type, vt_link)
                
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

    def _parse_vt_response(self, result: Dict, original_ioc: str, ioc_type: str, vt_link: str) -> Dict:
        """Parse and extract relevant information from the VT API response."""
        data = result.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Extract detection statistics
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
        
        detection_percentage = round(((malicious + suspicious) / total) * 100, 1)
        detection_ratio = f"{malicious + suspicious}/{total}"
        
        # Get last analysis date
        last_analysis_date = ""
        if attributes.get("last_analysis_date"):
            last_analysis_date = datetime.fromtimestamp(
                attributes["last_analysis_date"]
            ).strftime('%Y-%m-%d %H:%M:%S')
        
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

        # Update counters for reporting
        if malicious + suspicious > 0:
            if malicious > 0:
                self.malicious_count += 1
            else:
                self.suspicious_count += 1
                
            # Count critical findings
            if (malicious + suspicious) / total > 0.5:
                self.critical_count += 1
                
            # Print detection information for malicious IOCs
            if ioc_type == "url" or ioc_type == "domain":
                # Mask the actual URL/domain in terminal output for safety
                masked_ioc = original_ioc[:5] + "*****" + original_ioc[-5:] if len(original_ioc) > 10 else original_ioc
                print(f"\n{BOLD}{masked_ioc}{RESET} ({ioc_type}):")
            else:
                print(f"\n{BOLD}{original_ioc}{RESET} ({ioc_type}):")
            
            self.print_detection_bar(malicious + suspicious, total)
        
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
            "error": "",
            # Include raw results for better MS detection
            "last_analysis_results": attributes.get("last_analysis_results", {})
        }
        
        return result

    def process_file(self, file_path: str, output_path: Optional[str] = None) -> List[Dict]:
        """
        Process a file containing IOCs with premium API optimizations.
        
        Args:
            file_path: Path to file containing IOCs
            output_path: Optional path for CSV output
            
        Returns:
            List of result dictionaries for each IOC
        """
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
        iocs = self._parse_input_file(file_path)

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

        # Process the IOCs in parallel with a progress bar
        results = self._process_iocs_parallel(iocs)
        self.results_list = results
        
        # Calculate scan duration
        scan_duration = time.time() - self.scan_start_time
        scan_duration_str = f"{int(scan_duration // 60)}m {int(scan_duration % 60)}s"
        
        # Export results to CSV
        self._export_to_csv(results, output_path)
        
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

    def _parse_input_file(self, file_path: Path) -> List[Dict]:
        """Parse the input file to extract IOCs."""
        iocs = []
        try:
            # Try to determine file type by extension
            file_ext = file_path.suffix.lower()
            
            if file_ext in ['.xlsx', '.xls']:
                # Excel file
                try:
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
                                ioc_type = IOCHelper.identify_type(value)
                                iocs.append({"ioc": value, "ioc_type": ioc_type})
                except Exception as e:
                    print(f"{RED}Error reading Excel file: {str(e)}{RESET}")
            else:
                # Treat as text file (CSV, TXT, etc.)
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            ioc_type = IOCHelper.identify_type(line)
                            iocs.append({"ioc": line, "ioc_type": ioc_type})
        except Exception as e:
            print(f"{RED}Error reading file: {str(e)}{RESET}")
            return []
            
        return iocs

    def _process_iocs_parallel(self, iocs: List[Dict]) -> List[Dict]:
        """Process IOCs in parallel using ThreadPoolExecutor."""
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
                    
        return results

    def _export_to_csv(self, results: List[Dict], output_path: Path) -> None:
        """Export results to CSV file."""
        # Convert to DataFrame for easier processing
        try:
            self.dataframe = pd.DataFrame(results)
            
            # Ensure vt_detection_percentage is numeric
            if 'vt_detection_percentage' in self.dataframe.columns:
                self.dataframe['vt_detection_percentage'] = pd.to_numeric(
                    self.dataframe['vt_detection_percentage'], errors='coerce')
                
            # Remove raw results column before saving to CSV
            if 'last_analysis_results' in self.dataframe.columns:
                self.dataframe = self.dataframe.drop(columns=['last_analysis_results'])
                
            # Save to CSV
            self.dataframe.to_csv(output_path, index=False)
            print(f"\n{GREEN}Results exported to CSV: {output_path}{RESET}")
        except Exception as e:
            print(f"{RED}Error exporting to CSV: {str(e)}{RESET}")
    
    def generate_html_report(self, input_filename: str, output_path: Optional[str] = None) -> Optional[str]:
        """
        Generate an HTML report from the scan results.
        
        Args:
            input_filename: Original input filename for display
            output_path: Optional path for HTML output
            
        Returns:
            Path to generated HTML report or None on failure
        """
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
        try:
            report_path = generate_html_report(
                self.results_list, 
                scan_stats, 
                output_path=output_path, 
                input_filename=input_filename
            )
            return report_path
        except Exception as e:
            print(f"{RED}Error generating HTML report: {str(e)}{RESET}")
            return None


class VirusTotalBatchScanner:
    """
    A class for processing IOCs in batch mode for Premium API usage efficiency.
    Provides specialized methods for batching various IOC types.
    """
    
    def __init__(self, api_key: str, batch_size: int = 100):
        """
        Initialize batch scanner.
        
        Args:
            api_key: VirusTotal API key
            batch_size: Maximum number of IOCs to batch in one request
        """
        self.api_key = api_key
        self.batch_size = min(batch_size, 200)  # Maximum batch size
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": api_key,
            "User-Agent": "VTBatchScanner/1.1.0 (Premium)"
        })
        self.session.verify = False
        self.base_url = "https://www.virustotal.com/api/v3"
        
    def batch_process_hashes(self, hashes: List[str]) -> Dict:
        """
        Process a batch of file hashes using Premium API's batch endpoint.
        
        Args:
            hashes: List of file hashes to check
            
        Returns:
            Dict: API response
        """
        if not hashes:
            return {}
        
        url = f"{self.base_url}/files"
        data = {"data": {"hashes": hashes}}
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error in batch processing hashes: {e}")
            return {}
    
    def batch_process_urls(self, urls: List[str]) -> Dict:
        """
        Process a batch of URLs using Premium API's batch endpoint.
        
        Args:
            urls: List of URLs to check
            
        Returns:
            Dict: API response
        """
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
                logger.error(f"Error encoding URL {url}: {e}")
                
        if not encoded_urls:
            return {}
            
        url = f"{self.base_url}/urls/batch"
        data = {"data": {"urls": encoded_urls}}
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error in batch processing URLs: {e}")
            return {}
            
    def batch_process_ips(self, ips: List[str]) -> Dict:
        """
        Process a batch of IPs using Premium API endpoint.
        Note: VT API doesn't have a true batch endpoint for IPs,
        but Premium API allows higher rate limits.
        
        Args:
            ips: List of IP addresses to check
            
        Returns:
            Dict: Combined API responses
        """
        results = {}
        for ip in ips:
            try:
                url = f"{self.base_url}/ip_addresses/{ip}"
                response = self.session.get(url)
                response.raise_for_status()
                results[ip] = response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"Error processing IP {ip}: {e}")
                results[ip] = {"error": str(e)}
        return results
    
    def batch_process_domains(self, domains: List[str]) -> Dict:
        """
        Process a batch of domains using Premium API endpoint.
        Note: VT API doesn't have a true batch endpoint for domains,
        but Premium API allows higher rate limits.
        
        Args:
            domains: List of domains to check
            
        Returns:
            Dict: Combined API responses
        """
        results = {}
        for domain in domains:
            try:
                url = f"{self.base_url}/domains/{domain}"
                response = self.session.get(url)
                response.raise_for_status()
                results[domain] = response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"Error processing domain {domain}: {e}")
                results[domain] = {"error": str(e)}
        return results


def main():
    """
    Main function: Parse arguments, initialize scanner, and run scan.
    Provides interactive command-line interface if not run with arguments.
    """
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}VirusTotal IOC Scanner (Premium Version){RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"\n{BLUE}This tool uses the Premium VirusTotal API for high-throughput scanning.{RESET}")
    print(f"{YELLOW}Features static HTML report generation and enhanced visualizations.{RESET}")
    
    # Get API key
    api_key = APIKeyManager.load() or os.environ.get("VT_API_KEY")
    if api_key:
        if input(f"\n{BOLD}Use saved API key? (Y/n): {RESET}").lower() == 'n':
            api_key = getpass.getpass(f"{BOLD}Enter your VirusTotal Premium API key: {RESET}")
    else:
        print(f"\n{YELLOW}No saved API key found.{RESET}")
        api_key = getpass.getpass(f"{BOLD}Enter your VirusTotal Premium API key: {RESET}")

    if not api_key:
        print(f"{RED}Error: No API key provided. Exiting.{RESET}")
        sys.exit(1)

    if not APIKeyManager.load() and input(f"{BOLD}Save this API key? (Y/n): {RESET}").lower() != 'n':
        if APIKeyManager.save(api_key):
            print(f"{GREEN}API key saved successfully.{RESET}")
        else:
            print(f"{YELLOW}Failed to save API key.{RESET}")

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
    scanner = VirusTotalScanner(api_key, max_workers=max_workers, scan_mode="premium")
    results = scanner.process_file(input_file, csv_output_file)
    
    # Generate HTML report if there are results
    if results:
        html_path = scanner.generate_html_report(input_file, html_output_file)
        if html_path:
            print(f"\n{GREEN}HTML report generated: {html_path}{RESET}")
    
    print(f"\n{GREEN}Thank you for using the VirusTotal IOC Scanner!{RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Process interrupted by user. Exiting.{RESET}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\n{RED}An unexpected error occurred: {str(e)}{RESET}")
        print(f"{YELLOW}Check vt_scanner.log for details.{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
