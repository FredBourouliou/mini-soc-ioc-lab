#!/usr/bin/env python3
"""
Main IOC Scanner Module - Entry point for SOC threat detection
Demonstrates: IOC ingestion, file/process/log scanning, YARA integration, reporting
"""

import argparse
import hashlib
import html as html_lib
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import psutil
import yara

from utils import (
    setup_logging,
    calculate_file_hash,
    parse_ioc_line,
    is_valid_ip,
    is_valid_domain,
    format_timestamp
)
from yara_integration import YaraScanner
from osint_enrich import OSINTEnricher


def md_inline(value: Any) -> str:
    """Make a value safe to put inside a Markdown inline code span."""
    return str(value).replace('`', "'").replace('\r', ' ').replace('\n', ' ')


class IOCScanner:
    """Main scanner class coordinating IOC detection across files, processes, and logs"""

    def __init__(self, ioc_file: str, yara_rules: Optional[str] = None,
                 enrich: bool = False, verbose: bool = False):
        # Initialize scanner with IOC list and optional YARA rules
        self.logger = setup_logging(verbose)
        self.iocs = self.load_iocs(ioc_file)
        self.yara_scanner = YaraScanner(yara_rules) if yara_rules else None
        self.enricher = OSINTEnricher() if enrich else None
        self.detections = []

    def load_iocs(self, ioc_file: str) -> Dict[str, List[Dict]]:
        """Load and parse IOC indicators from file - fundamental SOC task"""
        iocs = {
            'hashes': {'md5': {}, 'sha1': {}, 'sha256': {}},
            'ips': {},
            'domains': {},
            'yara_refs': {}
        }

        try:
            with open(ioc_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    try:
                        ioc_type, value, metadata = parse_ioc_line(line)

                        if ioc_type == 'HASH':
                            hash_type, hash_value = value.split(':', 1)
                            if hash_type in iocs['hashes']:
                                iocs['hashes'][hash_type][hash_value.lower()] = metadata

                        elif ioc_type == 'IP' and is_valid_ip(value):
                            iocs['ips'][value] = metadata

                        elif ioc_type == 'DOMAIN' and is_valid_domain(value):
                            iocs['domains'][value.lower()] = metadata

                        elif ioc_type == 'YARA':
                            iocs['yara_refs'][value] = metadata

                    except Exception as e:
                        self.logger.warning(f"Error parsing IOC line {line_num}: {e}")

        except FileNotFoundError:
            self.logger.error(f"IOC file not found: {ioc_file}")
            sys.exit(1)

        self.logger.info(f"Loaded {sum(len(v) if isinstance(v, dict) else 0 for v in iocs.values())} IOCs")
        return iocs

    def scan_files(self, paths: List[str]) -> List[Dict]:
        """Scan files for IOC matches - core detection capability"""
        results = []

        for path in paths:
            path_obj = Path(path)

            if path_obj.is_file():
                results.extend(self._scan_single_file(path_obj))
            elif path_obj.is_dir():
                # Recursively scan directory
                for file_path in path_obj.rglob('*'):
                    if file_path.is_file():
                        results.extend(self._scan_single_file(file_path))

        return results

    def _scan_single_file(self, file_path: Path) -> List[Dict]:
        """Scan individual file for IOCs and YARA matches"""
        detections = []

        try:
            # Calculate file hashes for comparison
            file_hashes = {
                'md5': calculate_file_hash(file_path, 'md5'),
                'sha1': calculate_file_hash(file_path, 'sha1'),
                'sha256': calculate_file_hash(file_path, 'sha256')
            }

            # Check hash IOCs
            for hash_type, hash_value in file_hashes.items():
                if hash_value in self.iocs['hashes'][hash_type]:
                    detection = {
                        'type': 'HASH',
                        'subtype': hash_type.upper(),
                        'value': hash_value,
                        'path': str(file_path),
                        'metadata': self.iocs['hashes'][hash_type][hash_value],
                        'timestamp': format_timestamp(),
                        'severity': 'HIGH'
                    }

                    # Enrich if enabled
                    if self.enricher:
                        detection['enrichment'] = self.enricher.enrich_hash(hash_value)

                    detections.append(detection)
                    self.logger.warning(f"IOC Match: {hash_type} {hash_value} - {file_path}")

            # Apply YARA rules if configured
            if self.yara_scanner:
                yara_matches = self.yara_scanner.scan_file(str(file_path))
                for match in yara_matches:
                    detection = {
                        'type': 'YARA',
                        'rule': match['rule'],
                        'path': str(file_path),
                        'strings': match.get('strings', []),
                        'timestamp': format_timestamp(),
                        'severity': 'MEDIUM'
                    }
                    detections.append(detection)
                    self.logger.warning(f"YARA Match: {match['rule']} - {file_path}")

        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")

        return detections

    def scan_processes(self) -> List[Dict]:
        """Scan running processes for suspicious indicators"""
        detections = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info

                # Check process executable hash if accessible
                if proc_info.get('exe'):
                    exe_path = Path(proc_info['exe'])
                    if exe_path.exists():
                        exe_hash = calculate_file_hash(exe_path, 'sha256')

                        if exe_hash in self.iocs['hashes']['sha256']:
                            detection = {
                                'type': 'PROCESS',
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'path': proc_info['exe'],
                                'hash': exe_hash,
                                'metadata': self.iocs['hashes']['sha256'][exe_hash],
                                'timestamp': format_timestamp(),
                                'severity': 'CRITICAL'
                            }
                            detections.append(detection)
                            self.logger.critical(f"Malicious process detected: {proc_info['name']} (PID: {proc_info['pid']})")

                # Check command line for IOCs
                cmdline = ' '.join(proc_info.get('cmdline', []))
                for ip in self.iocs['ips']:
                    if ip in cmdline:
                        detection = {
                            'type': 'PROCESS_NETWORK',
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'ioc': ip,
                            'executable': (proc_info.get('cmdline') or [''])[0],  # never the full cmdline: it may hold secrets
                            'timestamp': format_timestamp(),
                            'severity': 'HIGH'
                        }
                        detections.append(detection)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return detections

    def scan_logs(self, log_paths: List[str]) -> List[Dict]:
        """Parse logs for IOC indicators - critical for incident response"""
        detections = []

        for log_path in log_paths:
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        # Check for IP IOCs
                        for ip in self.iocs['ips']:
                            if ip in line:
                                detection = {
                                    'type': 'LOG_IP',
                                    'path': log_path,
                                    'line': line_num,
                                    'ioc': ip,
                                    'context': line.strip()[:200],  # First 200 chars
                                    'metadata': self.iocs['ips'][ip],
                                    'timestamp': format_timestamp(),
                                    'severity': 'MEDIUM'
                                }
                                detections.append(detection)

                        # Check for domain IOCs
                        for domain in self.iocs['domains']:
                            if domain in line.lower():
                                detection = {
                                    'type': 'LOG_DOMAIN',
                                    'path': log_path,
                                    'line': line_num,
                                    'ioc': domain,
                                    'context': line.strip()[:200],
                                    'metadata': self.iocs['domains'][domain],
                                    'timestamp': format_timestamp(),
                                    'severity': 'MEDIUM'
                                }
                                detections.append(detection)

            except Exception as e:
                self.logger.error(f"Error scanning log {log_path}: {e}")

        return detections

    def generate_report(self, output_file: str, format: str = 'markdown'):
        """Generate detection report - essential for SOC workflow"""
        if format == 'markdown':
            self._generate_markdown_report(output_file)
        elif format == 'json':
            self._generate_json_report(output_file)
        elif format == 'html':
            self._generate_html_report(output_file)
        else:
            self.logger.error(f"Unsupported report format: {format}")

    def _generate_markdown_report(self, output_file: str):
        """Generate Markdown format report for easy reading"""
        with open(output_file, 'w') as f:
            f.write("# IOC Detection Report\n\n")
            f.write(f"**Generated:** {format_timestamp()}\n")
            f.write(f"**Total Detections:** {len(self.detections)}\n\n")

            # Summary by type
            f.write("## Summary\n\n")
            type_counts = {}
            for det in self.detections:
                type_counts[det['type']] = type_counts.get(det['type'], 0) + 1

            f.write("| Detection Type | Count |\n")
            f.write("|----------------|-------|\n")
            for det_type, count in type_counts.items():
                f.write(f"| {det_type} | {count} |\n")

            # Detailed findings
            f.write("\n## Detailed Findings\n\n")

            for i, detection in enumerate(self.detections, 1):
                f.write(f"### Detection #{i}\n\n")
                f.write(f"- **Type:** {detection['type']}\n")
                f.write(f"- **Severity:** {detection.get('severity', 'UNKNOWN')}\n")
                f.write(f"- **Timestamp:** {detection['timestamp']}\n")

                if 'path' in detection:
                    f.write(f"- **Path:** `{md_inline(detection['path'])}`\n")
                if 'value' in detection:
                    f.write(f"- **Value:** `{md_inline(detection['value'])}`\n")
                if 'rule' in detection:
                    f.write(f"- **YARA Rule:** {detection['rule']}\n")
                if 'metadata' in detection:
                    f.write(f"- **Metadata:** `{md_inline(detection['metadata'])}`\n")
                if 'enrichment' in detection:
                    f.write(f"- **Enrichment:** {json.dumps(detection['enrichment'], indent=2)}\n")

                f.write("\n")

            # Recommendations
            f.write("## Recommended Actions\n\n")
            f.write("- [ ] Isolate affected systems\n")
            f.write("- [ ] Collect forensic artifacts\n")
            f.write("- [ ] Check for lateral movement\n")
            f.write("- [ ] Review security logs for related activity\n")
            f.write("- [ ] Update IOC watchlists\n")
            f.write("- [ ] Document incident timeline\n")

    def _generate_json_report(self, output_file: str):
        """Generate JSON format report for automation"""
        report = {
            'timestamp': format_timestamp(),
            'total_detections': len(self.detections),
            'detections': self.detections
        }

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

    def _generate_html_report(self, output_file: str):
        """Generate HTML format report for presentation"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
    <title>IOC Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #d32f2f; }}
        h2 {{ color: #1976d2; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .critical {{ background-color: #ffebee; }}
        .high {{ background-color: #fff3e0; }}
        .medium {{ background-color: #fff9c4; }}
    </style>
</head>
<body>
    <h1>IOC Detection Report</h1>
    <p><strong>Generated:</strong> {format_timestamp()}</p>
    <p><strong>Total Detections:</strong> {len(self.detections)}</p>

    <h2>Detections</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Details</th>
            <th>Timestamp</th>
        </tr>
"""

        for det in self.detections:
            esc = lambda v: html_lib.escape(str(v), quote=True)  # noqa: E731
            severity = det.get('severity', 'UNKNOWN')
            details = json.dumps({k: v for k, v in det.items()
                                 if k not in ['type', 'severity', 'timestamp']},
                                indent=2)
            html += f"""
        <tr class="{esc(severity.lower())}">
            <td>{esc(det['type'])}</td>
            <td>{esc(severity)}</td>
            <td><pre>{esc(details)}</pre></td>
            <td>{esc(det['timestamp'])}</td>
        </tr>
"""

        html += """
    </table>
</body>
</html>
"""

        with open(output_file, 'w') as f:
            f.write(html)

    def run_scan(self, targets: List[str], scan_processes: bool = True,
                 log_paths: Optional[List[str]] = None):
        """Execute full scan workflow - main entry point"""
        self.logger.info("Starting IOC scan...")

        # File scanning
        if targets:
            self.logger.info(f"Scanning {len(targets)} target paths...")
            file_detections = self.scan_files(targets)
            self.detections.extend(file_detections)

        # Process scanning
        if scan_processes:
            self.logger.info("Scanning running processes...")
            proc_detections = self.scan_processes()
            self.detections.extend(proc_detections)

        # Log scanning
        if log_paths:
            self.logger.info(f"Scanning {len(log_paths)} log files...")
            log_detections = self.scan_logs(log_paths)
            self.detections.extend(log_detections)

        self.logger.info(f"Scan complete. Total detections: {len(self.detections)}")
        return self.detections


def main():
    """CLI entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description='Mini SOC IOC Lab - Threat Detection Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.scan_ioc --targets /path/to/scan --ioc ioc/ioc_list.txt --output report.md
  python -m src.scan_ioc --targets ~/Downloads --ioc ioc/ioc_list.txt --yara yara/rules.yar --enrich
  python -m src.scan_ioc --targets /var/log --ioc ioc/ioc_list.txt --format json --output detections.json
        """
    )

    parser.add_argument('--targets', nargs='+', help='Paths to scan (files or directories)')
    parser.add_argument('--ioc', required=True, help='Path to IOC list file')
    parser.add_argument('--yara', help='Path to YARA rules file')
    parser.add_argument('--logs', nargs='+', help='Log files to scan')
    parser.add_argument('--output', default='report.md', help='Output report file')
    parser.add_argument('--format', choices=['markdown', 'json', 'html'],
                       default='markdown', help='Report format')
    parser.add_argument('--enrich', action='store_true',
                       help='Enable OSINT enrichment (requires network)')
    parser.add_argument('--no-processes', action='store_true',
                       help='Skip process scanning')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--docker-mode', action='store_true',
                       help='Docker-optimized mode (skip process scanning)')

    args = parser.parse_args()

    # Validate inputs
    if not args.targets and not args.logs and not args.docker_mode:
        parser.error('Either --targets or --logs must be specified')

    # Initialize scanner
    scanner = IOCScanner(
        ioc_file=args.ioc,
        yara_rules=args.yara,
        enrich=args.enrich,
        verbose=args.verbose
    )

    # Run scan
    scan_processes = not args.no_processes and not args.docker_mode
    detections = scanner.run_scan(
        targets=args.targets or [],
        scan_processes=scan_processes,
        log_paths=args.logs
    )

    # Generate report
    scanner.generate_report(args.output, args.format)
    print(f"\n[+] Scan complete. Report saved to: {args.output}")

    # Exit with error code if detections found
    if detections:
        print(f"[!] {len(detections)} IOC detection(s) found!")
        sys.exit(1)
    else:
        print("[+] No IOCs detected.")
        sys.exit(0)


if __name__ == '__main__':
    main()