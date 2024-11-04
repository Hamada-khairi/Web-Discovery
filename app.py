import socket
import ipaddress
import concurrent.futures
import subprocess
import logging
import json
import yaml
import argparse
from datetime import datetime
from pathlib import Path
import sys
import time
import csv
from typing import Dict, List, Optional, Tuple, Any
import platform
import ssl
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class NetworkScanner:
    """Enterprise-grade network scanning tool for discovering web services."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize scanner with configuration."""
        self.logger = self._setup_logging()
        self.config = self._load_config(config_path)
        self.results: List[Dict[str, Any]] = []
        self.start_time = None
        self.end_time = None
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging with both file and console handlers."""
        logger = logging.getLogger("NetworkScanner")
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        Path("logs").mkdir(exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler(
            f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file with fallback defaults."""
        default_config = {
            "ports": {
                "web": [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 8888],
                "additional": [21, 22, 25, 53, 110, 143, 3306, 5432]
            },
            "timeout": {
                "port": 1,
                "http": 3
            },
            "threads": {
                "host": 50,
                "port": 10
            },
            "http": {
                "paths": ["/", "/robots.txt", "/sitemap.xml"],
                "verify_ssl": False
            },
            "output": {
                "formats": ["json", "csv"],
                "directory": "scan_results"
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
            return config
        except FileNotFoundError:
            self.logger.warning(f"Config file {config_path} not found, using defaults")
            return default_config

    async def get_ssl_info(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information for HTTPS services."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.config['timeout']['port']) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    return {
                        "issuer": ssock.getpeercert()['issuer'],
                        "expires": ssock.getpeercert()['notAfter'],
                        "subject": ssock.getpeercert()['subject']
                    }
        except Exception as e:
            self.logger.debug(f"SSL info collection failed for {ip}:{port} - {str(e)}")
            return None

    def get_web_info(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Gather information about web services."""
        protocol = "https" if port in [443, 8443] else "http"
        info = {"headers": {}, "title": None, "response_code": None}
        
        for path in self.config['http']['paths']:
            url = f"{protocol}://{ip}:{port}{path}"
            try:
                response = requests.get(
                    url,
                    timeout=self.config['timeout']['http'],
                    verify=self.config['http']['verify_ssl'],
                    allow_redirects=True
                )
                info["response_code"] = response.status_code
                info["headers"] = dict(response.headers)
                
                # Try to extract page title
                if path == "/" and response.text:
                    import re
                    title_match = re.search('<title>(.*?)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        info["title"] = title_match.group(1)
                
                return info
            except requests.RequestException as e:
                self.logger.debug(f"Web info collection failed for {url} - {str(e)}")
                continue
        return None

    def scan_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Enhanced port scanning with service detection."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config['timeout']['port'])
        
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                service_info = {
                    "port": port,
                    "state": "open",
                    "service": None,
                    "web_info": None,
                    "ssl_info": None
                }
                
                try:
                    service_info["service"] = socket.getservbyport(port)
                except:
                    service_info["service"] = "unknown"
                
                # Gather additional information for web ports
                if port in self.config['ports']['web']:
                    service_info["web_info"] = self.get_web_info(ip, port)
                    if port in [443, 8443]:
                        service_info["ssl_info"] = self.get_ssl_info(ip, port)
                
                return service_info
        except Exception as e:
            self.logger.debug(f"Port scan failed for {ip}:{port} - {str(e)}")
        finally:
            sock.close()
        return None

    def scan_host(self, ip: str) -> Optional[Dict[str, Any]]:
        """Comprehensive host scanning with multiple service detection."""
        active_ports = []
        all_ports = self.config['ports']['web'] + self.config['ports']['additional']
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['threads']['port']) as executor:
            port_futures = [
                executor.submit(self.scan_port, ip, port) 
                for port in all_ports
            ]
            
            for future in concurrent.futures.as_completed(port_futures):
                try:
                    result = future.result()
                    if result:
                        active_ports.append(result)
                except Exception as e:
                    self.logger.error(f"Error scanning ports on {ip}: {str(e)}")
        
        if active_ports:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            
            return {
                'ip': ip,
                'hostname': hostname,
                'timestamp': datetime.now().isoformat(),
                'ports': active_ports,
                'os_detection': self.detect_os(ip)
            }
        return None

    def detect_os(self, ip: str) -> Optional[str]:
        """Attempt OS detection using TTL values and other indicators."""
        try:
            if platform.system().lower() == "windows":
                ping_param = "-n"
            else:
                ping_param = "-c"
            
            result = subprocess.run(
                ["ping", ping_param, "1", ip],
                capture_output=True,
                text=True
            )
            
            # Basic OS detection based on TTL
            if "TTL=" in result.stdout or "ttl=" in result.stdout:
                ttl_line = [line for line in result.stdout.split('\n') if 'TTL=' in line.upper()][0]
                ttl = int(''.join(filter(str.isdigit, ttl_line.split('TTL=')[1])))
                
                if ttl <= 64:
                    return "Linux/Unix"
                elif ttl <= 128:
                    return "Windows"
                else:
                    return "Network Equipment"
        except Exception as e:
            self.logger.debug(f"OS detection failed for {ip}: {str(e)}")
        return None

    def scan_network(self, network: str) -> List[Dict[str, Any]]:
        """Scan entire network with progress tracking."""
        self.start_time = datetime.now()
        self.logger.info(f"Starting network scan of {network} at {self.start_time}")
        
        try:
            network = ipaddress.ip_network(network)
        except ValueError as e:
            self.logger.error(f"Invalid network address: {e}")
            return []
        
        total_hosts = sum(1 for _ in network.hosts())
        scanned_hosts = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['threads']['host']) as executor:
            host_futures = {
                executor.submit(self.scan_host, str(ip)): str(ip) 
                for ip in network.hosts()
            }
            
            for future in concurrent.futures.as_completed(host_futures):
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        self.logger.info(
                            f"Found active host: {result['ip']} ({result['hostname']}) "
                            f"with {len(result['ports'])} open ports"
                        )
                except Exception as e:
                    ip = host_futures[future]
                    self.logger.error(f"Error scanning host {ip}: {str(e)}")
                
                scanned_hosts += 1
                if scanned_hosts % 10 == 0:
                    self.logger.info(f"Progress: {scanned_hosts}/{total_hosts} hosts scanned")
        
        self.end_time = datetime.now()
        self.generate_reports()
        return self.results

    def generate_reports(self) -> None:
        """Generate comprehensive reports in multiple formats."""
        if not self.results:
            self.logger.warning("No results to report")
            return
        
        # Create output directory
        output_dir = Path(self.config['output']['directory'])
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate summary
        summary = {
            "scan_start": self.start_time.isoformat(),
            "scan_end": self.end_time.isoformat(),
            "duration": str(self.end_time - self.start_time),
            "total_hosts": len(self.results),
            "total_open_ports": sum(len(host['ports']) for host in self.results)
        }
        
        # Save reports in configured formats
        for format_type in self.config['output']['formats']:
            if format_type == 'json':
                report_path = output_dir / f"scan_report_{timestamp}.json"
                with open(report_path, 'w') as f:
                    json.dump({
                        "summary": summary,
                        "results": self.results
                    }, f, indent=2)
            
            elif format_type == 'csv':
                report_path = output_dir / f"scan_report_{timestamp}.csv"
                with open(report_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['IP', 'Hostname', 'OS', 'Port', 'State', 'Service', 'Web Title', 'SSL Issuer'])
                    
                    for host in self.results:
                        for port in host['ports']:
                            web_title = port.get('web_info', {}).get('title', 'N/A')
                            ssl_issuer = 'N/A'
                            if port.get('ssl_info'):
                                ssl_issuer = str(port['ssl_info'].get('issuer', 'N/A'))
                            
                            writer.writerow([
                                host['ip'],
                                host['hostname'],
                                host.get('os_detection', 'Unknown'),
                                port['port'],
                                port['state'],
                                port['service'],
                                web_title,
                                ssl_issuer
                            ])
        
        self.logger.info(f"Reports generated in {output_dir}")

def main():
    parser = argparse.ArgumentParser(description='Production Network Scanner')
    parser.add_argument('network', help='Network to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    args = parser.parse_args()
    
    scanner = NetworkScanner(args.config)
    scanner.scan_network(args.network)

if __name__ == "__main__":
    main()

    # python app.py 192.168.1.0/24