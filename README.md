# 🛡️ VirusTotal IOC Scanner

<div align="center">
  
[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![VirusTotal API](https://img.shields.io/badge/API-VirusTotal-red.svg)](https://developers.virustotal.com/reference)
[![Dashboard](https://img.shields.io/badge/UI-Interactive_Dashboard-orange.svg)](https://dash.plotly.com/)

</div>

A powerful and streamlined tool for scanning Indicators of Compromise (IOCs) against the VirusTotal API, featuring an interactive dashboard, enhanced visualizations, and robust security measures.

## ✨ Features

- 🔍 **Comprehensive IOC Scanning**: Analyze IPs, domains, URLs, and file hashes against VirusTotal's database
- 📊 **Interactive Dashboard**: Visualize results with detailed graphs and filterable tables
- ⚡ **Premium API Optimization**: Efficiently utilizes VirusTotal Premium API capabilities
- 📦 **Batch Processing**: Optimized scanning of large sets of indicators
- 🧵 **Multi-threaded Execution**: Parallel scanning for improved performance
- 🔒 **Secure API Key Management**: Local encrypted storage of API credentials
- 🔍 **Advanced Filtering**: Sort and filter results by severity, IOC type, and detection rates
- 📋 **Export Options**: Save results to CSV for further analysis
- 📈 **Enhanced Visualizations**: Detection rate graphs and threat severity indicators
- ⏱️ **Smart Rate Limiting**: Automatic API request throttling to prevent quota issues

## 🚀 Installation

### Prerequisites

- 🐍 Python 3.6 or higher
- 🔑 VirusTotal API key (Premium recommended for best performance)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/danishnizmi/VTscanner.git
   cd VTscanner
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
   Alternatively, the script will automatically install required packages on first run.

## 📝 Usage

### Basic Usage

Run the script and follow the interactive prompts:

```bash
python vtscanner.py
```

The tool will guide you through:
1. Entering or selecting your VirusTotal API key
2. Specifying the input file containing IOCs
3. Setting the output file for results
4. Configuring parallel worker count (for Premium API)

### Input File Format

The input file should contain one IOC per line. The tool automatically detects the type of each IOC (IP, domain, URL, or hash).

Example:
```
8.8.8.8
malicious-domain.com
https://suspicious-url.com/path
44d88612fea8a8f36de82e1278abb02f
```

## 📊 Dashboard Features

The interactive dashboard provides:

- 📋 **Summary Cards**: At-a-glance view of total IOCs, malicious, suspicious, and clean counts
- 📊 **IOC Type Distribution**: Bar chart showing breakdown of different indicator types
- 🥧 **Severity Analysis**: Pie chart depicting detection severity distribution
- 🔍 **Advanced Filtering**: Filter results by IOC type, severity level, and custom search terms
- 📑 **Color-Coded Results**: Detailed data table with color-coded severity indicators
- ⚠️ **Critical Findings**: Highlighted section for high-priority threats requiring immediate attention
- 🔗 **Direct VT Links**: One-click access to VirusTotal's detailed analysis for each IOC

## 🔒 Security Features

- 🛡️ **Secure Storage**: API key saved with restricted file permissions
- 🧹 **IOC Sanitization**: Protection against code injection and script execution
- 🔐 **Connection Security**: Configurable SSL verification for API requests
- 👁️‍🗨️ **Safe Display**: Masked presentation of potentially malicious URLs/domains
- 🔄 **Error Handling**: Graceful management of API rate limits and connection issues

## 📁 Project Structure

- **vtscanner.py**: Main script containing the core scanning functionality
- **dashboard_template.py**: Dashboard interface and visualization components
- **requirements.txt**: Required Python dependencies

## ⚙️ API Optimization

The tool is optimized for VirusTotal's Premium API with features like:
- 📦 **Batch Processing**: Efficient handling of multiple file hashes and URLs
- 🚦 **Intelligent Throttling**: Adaptive request rates to stay within API limits
- 🔄 **Automatic Retries**: Smart retry logic for transient API errors
- 🧵 **Thread Management**: Optimized thread pooling for parallel execution

## 📋 Dependencies

```
requests         # HTTP library for API communication
tqdm             # Progress bar visualization
dash             # Dashboard framework
dash-bootstrap-components  # UI components
plotly           # Interactive graphs and charts
pandas           # Data manipulation and analysis
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

- [VirusTotal](https://www.virustotal.com/) for their comprehensive threat intelligence platform
- [Dash by Plotly](https://dash.plotly.com/) for the interactive visualization framework
- [Requests](https://requests.readthedocs.io/) for the HTTP library

## ⚠️ Disclaimer

This tool is provided for legitimate security research and incident response purposes only. Always ensure you have proper authorization before scanning any IOCs or accessing external services.

## 📞 Contact

For questions, feedback, or contributions, please open an issue on GitHub or reach out through the repository.

---

<div align="center">
  
Made with ❤️ for the cybersecurity community

</div>
