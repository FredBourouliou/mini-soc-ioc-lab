# Mini SOC IOC Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A comprehensive Security Operations Center (SOC) and Indicator of Compromise (IOC) laboratory for security training, threat detection, and incident response simulation.

## 🎯 Features

- **IOC Detection**: Scan files and systems for indicators of compromise
- **YARA Integration**: Advanced pattern matching for malware detection  
- **OSINT Enrichment**: Enrich IOCs with threat intelligence data
- **PowerShell Support**: Windows-native scanning capabilities
- **Docker Ready**: Containerized deployment for easy setup
- **Extensible Framework**: Easy to add new detection rules and IOC feeds

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run basic IOC scan
python src/scan_ioc.py --file samples/sample_malware.bin

# Run YARA scan
python src/yara_integration.py --target samples/

# Enrich IOCs with OSINT data
python src/osint_enrich.py --ioc-file ioc/ioc_list.txt
```

## 📁 Project Structure

```
mini-soc-ioc-lab/
├── src/                 # Core Python modules
│   ├── scan_ioc.py     # IOC scanning engine
│   ├── yara_integration.py  # YARA rules engine
│   └── osint_enrich.py # OSINT enrichment tools
├── yara/               # YARA detection rules
├── ioc/                # IOC feeds and lists
├── powershell/         # PowerShell scripts
├── tests/              # Unit tests
└── docs/               # Documentation
```

## 🐳 Docker Usage

```bash
# Build the image
docker build -t mini-soc-lab .

# Run the container
docker run -it -v $(pwd)/samples:/app/samples mini-soc-lab
```

## 📖 Documentation

See the [docs/](docs/) folder for detailed documentation including:
- [SOC Notes and Best Practices](docs/SOC_notes.md)
- API Documentation
- Detection Rule Writing Guide

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before scanning systems you don't own.
