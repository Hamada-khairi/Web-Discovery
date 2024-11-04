# Enterprise Network Discovery Tool

A comprehensive, production-ready network scanning and service discovery tool built for enterprise environments. This tool provides detailed insights about network services, web servers, SSL certificates, and operating systems while maintaining logs and generating detailed reports.

## 🚀 Features

- **Comprehensive Service Discovery**
  - Web server detection and analysis
  - SSL/TLS certificate information
  - Operating system detection
  - Service identification
  - Port state analysis

- **Enterprise-Grade Reporting**
  - JSON reports for programmatic processing
  - CSV reports for spreadsheet analysis
  - Detailed logging with rotation
  - Progress tracking
  - Summary statistics

- **Performance Optimized**
  - Multi-threaded scanning
  - Configurable thread pools
  - Timeout controls
  - Error handling and recovery

- **Security Focused**
  - Non-intrusive scanning methods
  - Configurable scan parameters
  - Rate limiting capabilities
  - SSL verification options

## 📋 Prerequisites

- Python 3.8 or higher
- Administrative privileges (for some scanning features)
- Network access to target systems

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

2. Create and activate a virtual environment:

On Windows:
```bash
python -m venv venv
.\venv\Scripts\activate.ps1
```

On Linux/MacOS:
```bash
python -m venv venv
source venv/bin/activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## 📄 Requirements.txt
```
requests>=2.28.0
pyyaml>=6.0
typing>=3.7.4
```

## ⚙️ Configuration

Create a `config.yaml` file in the project root:

```yaml
ports:
  web:
    - 80
    - 443
    - 8080
    - 8443
    - 3000
    - 4000
    - 5000
    - 8000
    - 8888
  additional:
    - 21    # FTP
    - 22    # SSH
    - 25    # SMTP
    - 53    # DNS
    - 3306  # MySQL
    - 5432  # PostgreSQL

timeout:
  port: 1    # seconds
  http: 3    # seconds

threads:
  host: 50   # concurrent hosts
  port: 10   # concurrent ports per host

http:
  paths:
    - "/"
    - "/robots.txt"
    - "/sitemap.xml"
  verify_ssl: false

output:
  formats:
    - json
    - csv
  directory: scan_results
```

## 🚀 Usage

Basic scan of a network:
```bash
python app.py --config config.yaml 192.168.1.0/24
```

Scan with custom config location:
```bash
python app.py --config /path/to/config.yaml 10.0.0.0/24
```

## 📊 Output

The tool generates multiple output files in the configured directory:

```plaintext
scan_results/
├── scan_report_20240104_153021.json
├── scan_report_20240104_153021.csv
└── logs/
    └── scan_20240104_153021.log
```

### JSON Report Structure:
```json
{
  "summary": {
    "scan_start": "2024-01-04T15:30:21.123456",
    "scan_end": "2024-01-04T15:35:42.654321",
    "duration": "0:05:21.530865",
    "total_hosts": 12,
    "total_open_ports": 47
  },
  "results": [
    {
      "ip": "192.168.1.100",
      "hostname": "webserver.local",
      "timestamp": "2024-01-04T15:30:25.123456",
      "os_detection": "Linux/Unix",
      "ports": [
        {
          "port": 80,
          "state": "open",
          "service": "http",
          "web_info": {
            "title": "Welcome Page",
            "headers": {},
            "response_code": 200
          }
        }
      ]
    }
  ]
}
```

## 🔍 Logging

Logs are stored in the `logs` directory with the following format:
```plaintext
2024-01-04 15:30:21,123 - NetworkScanner - INFO - Starting network scan of 192.168.1.0/24
2024-01-04 15:30:25,456 - NetworkScanner - INFO - Found active host: 192.168.1.100 (webserver.local)
```

## ⚠️ Security Considerations

1. **Authorization**: Ensure you have permission to scan the target network
2. **Rate Limiting**: Configure appropriate timeouts and thread counts
3. **Network Impact**: Be aware of bandwidth and system resource usage
4. **Sensitive Data**: Handle scan results securely
5. **Credentials**: Never store sensitive credentials in configuration files

## 🛠️ Troubleshooting

1. **Permission Errors**
   - Ensure the script runs with appropriate privileges
   - Check firewall settings
   - Verify network access

2. **Slow Scans**
   - Adjust thread counts in config
   - Check network connectivity
   - Verify timeout settings

3. **Missing Results**
   - Check log files for errors
   - Verify target network is accessible
   - Ensure correct CIDR notation

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Support

For support and questions:
- Create an issue in the repository
- Contact the maintainer
- Check the documentation

## 🔄 Changelog

### Version 1.0.0 (2024-01-04)
- Initial release
- Basic network scanning
- Web service detection
- Report generation

### Version 1.1.0 (2024-01-10)
- Added SSL certificate analysis
- Improved OS detection
- Enhanced error handling
- Performance optimizations
