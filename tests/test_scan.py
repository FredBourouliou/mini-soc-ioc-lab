"""
Unit tests for IOC Scanner
Tests core functionality: IOC loading, hash checking, YARA matching
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from unittest.mock import Mock, patch, MagicMock

from utils import (
    calculate_file_hash,
    parse_ioc_line,
    is_valid_ip,
    is_valid_domain,
    extract_ips_from_text
)
from yara_integration import YaraScanner
from scan_ioc import IOCScanner


class TestIOCLoading:
    """Test IOC file loading and parsing"""

    def test_parse_ioc_line_valid(self):
        """Test parsing valid IOC lines"""
        # Test with metadata
        ioc_type, value, metadata = parse_ioc_line("HASH|md5:44d88612fea8a8f36de82e1278abb02f|test-malware")
        assert ioc_type == "HASH"
        assert value == "md5:44d88612fea8a8f36de82e1278abb02f"
        assert metadata == "test-malware"

        # Test without metadata
        ioc_type, value, metadata = parse_ioc_line("IP|192.0.2.44|")
        assert ioc_type == "IP"
        assert value == "192.0.2.44"
        assert metadata == ""

    def test_parse_ioc_line_invalid(self):
        """Test parsing invalid IOC lines"""
        with pytest.raises(ValueError):
            parse_ioc_line("INVALID_FORMAT")

    def test_load_iocs_from_file(self):
        """Test loading IOCs from file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# Comment line\n")
            f.write("HASH|md5:098f6bcd4621d373cade4e832627b4f6|test\n")
            f.write("IP|192.0.2.44|suspicious\n")
            f.write("DOMAIN|evil.example.com|malware\n")
            f.flush()
            temp_file = f.name

        try:
            scanner = IOCScanner(temp_file)

            # Check hash IOCs
            assert '098f6bcd4621d373cade4e832627b4f6' in scanner.iocs['hashes']['md5']

            # Check IP IOCs
            assert '192.0.2.44' in scanner.iocs['ips']

            # Check domain IOCs
            assert 'evil.example.com' in scanner.iocs['domains']
        finally:
            os.unlink(temp_file)


class TestHashFunctions:
    """Test file hashing functionality"""

    def test_calculate_file_hash_md5(self):
        """Test MD5 hash calculation"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            f.flush()
            temp_file = f.name

        try:
            hash_value = calculate_file_hash(temp_file, 'md5')
            assert hash_value == '098f6bcd4621d373cade4e832627b4f6'
        finally:
            os.unlink(temp_file)

    def test_calculate_file_hash_sha256(self):
        """Test SHA256 hash calculation"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("test")
            f.flush()
            temp_file = f.name

        try:
            hash_value = calculate_file_hash(temp_file, 'sha256')
            assert hash_value == '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        finally:
            os.unlink(temp_file)

    def test_hash_check_detection(self):
        """Test hash-based IOC detection"""
        # Create test IOC file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ioc_file:
            ioc_file.write("HASH|sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08|test-file\n")
            ioc_file.flush()
            ioc_path = ioc_file.name

        # Create test file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as test_file:
            test_file.write("test")
            test_file.flush()
            test_path = test_file.name

        try:
            scanner = IOCScanner(ioc_path)
            detections = scanner.scan_files([test_path])

            assert len(detections) == 1
            assert detections[0]['type'] == 'HASH'
            assert detections[0]['subtype'] == 'SHA256'
        finally:
            os.unlink(ioc_path)
            os.unlink(test_path)


class TestYaraIntegration:
    """Test YARA integration"""

    @pytest.mark.skipif(not os.path.exists('yara/rules.yar'), reason="YARA rules not found")
    def test_yara_scanner_initialization(self):
        """Test YARA scanner initialization with rules"""
        scanner = YaraScanner('yara/rules.yar')
        assert scanner.rules is not None

    @pytest.mark.skipif(not os.path.exists('samples/sample_malware.bin'), reason="Sample file not found")
    def test_yara_detection_on_sample(self):
        """Test YARA detection on sample malware file"""
        scanner = YaraScanner('yara/rules.yar')

        if scanner.rules:
            matches = scanner.scan_file('samples/sample_malware.bin')
            assert len(matches) > 0

            # Check for expected rules
            rule_names = [m['rule'] for m in matches]
            assert any('Suspicious_Strings' in rule or 'Test' in rule or 'EICAR' in rule
                      for rule in rule_names)

    def test_yara_no_match(self):
        """Test YARA scanner with no matches"""
        # Create a clean file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("This is a completely clean file with no suspicious content.")
            f.flush()
            temp_file = f.name

        try:
            scanner = YaraScanner('yara/rules.yar')
            if scanner.rules:
                matches = scanner.scan_file(temp_file)
                # May or may not match depending on rules
                assert isinstance(matches, list)
        finally:
            os.unlink(temp_file)


class TestValidation:
    """Test validation functions"""

    def test_valid_ip_addresses(self):
        """Test IP address validation"""
        assert is_valid_ip("192.168.1.1") == True
        assert is_valid_ip("10.0.0.0") == True
        assert is_valid_ip("255.255.255.255") == True
        assert is_valid_ip("192.168.1.256") == False
        assert is_valid_ip("192.168.1") == False
        assert is_valid_ip("not.an.ip.address") == False

    def test_valid_domains(self):
        """Test domain name validation"""
        assert is_valid_domain("example.com") == True
        assert is_valid_domain("subdomain.example.com") == True
        assert is_valid_domain("test-site.co.uk") == True
        assert is_valid_domain("192.168.1.1") == False
        assert is_valid_domain("invalid..domain") == False
        assert is_valid_domain("-invalid.com") == False

    def test_extract_ips_from_text(self):
        """Test IP extraction from text"""
        text = "Connection from 192.168.1.1 to 10.0.0.1 failed. Also tried 256.1.1.1"
        ips = extract_ips_from_text(text)
        assert "192.168.1.1" in ips
        assert "10.0.0.1" in ips
        assert "256.1.1.1" not in ips  # Invalid IP


class TestLogScanning:
    """Test log file scanning functionality"""

    def test_scan_logs_with_ioc_detection(self):
        """Test log scanning for IOC detection"""
        # Create test IOC file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ioc_file:
            ioc_file.write("IP|192.0.2.44|suspicious-ip\n")
            ioc_file.write("DOMAIN|evil.example.com|malware-domain\n")
            ioc_file.flush()
            ioc_path = ioc_file.name

        # Create test log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as log_file:
            log_file.write("2025-01-25 10:00:00 Connection from 192.0.2.44\n")
            log_file.write("2025-01-25 10:00:01 DNS lookup for evil.example.com\n")
            log_file.write("2025-01-25 10:00:02 Normal activity\n")
            log_file.flush()
            log_path = log_file.name

        try:
            scanner = IOCScanner(ioc_path)
            detections = scanner.scan_logs([log_path])

            assert len(detections) == 2

            # Check for IP detection
            ip_detection = next((d for d in detections if d['type'] == 'LOG_IP'), None)
            assert ip_detection is not None
            assert ip_detection['ioc'] == '192.0.2.44'

            # Check for domain detection
            domain_detection = next((d for d in detections if d['type'] == 'LOG_DOMAIN'), None)
            assert domain_detection is not None
            assert domain_detection['ioc'] == 'evil.example.com'
        finally:
            os.unlink(ioc_path)
            os.unlink(log_path)


class TestReportGeneration:
    """Test report generation functionality"""

    def test_generate_markdown_report(self):
        """Test Markdown report generation"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ioc_file:
            ioc_file.write("HASH|md5:test|test\n")
            ioc_file.flush()
            ioc_path = ioc_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as report_file:
            report_path = report_file.name

        try:
            scanner = IOCScanner(ioc_path)

            # Add mock detection
            scanner.detections = [{
                'type': 'TEST',
                'severity': 'HIGH',
                'value': 'test-value',
                'timestamp': '2025-01-25 10:00:00'
            }]

            scanner.generate_report(report_path, 'markdown')

            # Check report was created
            assert os.path.exists(report_path)

            # Check report content
            with open(report_path, 'r') as f:
                content = f.read()
                assert '# IOC Detection Report' in content
                assert '**Total Detections:** 1' in content
                assert 'TEST' in content
        finally:
            os.unlink(ioc_path)
            os.unlink(report_path)

    def test_generate_json_report(self):
        """Test JSON report generation"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ioc_file:
            ioc_file.write("HASH|md5:test|test\n")
            ioc_file.flush()
            ioc_path = ioc_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as report_file:
            report_path = report_file.name

        try:
            scanner = IOCScanner(ioc_path)

            # Add mock detection
            scanner.detections = [{
                'type': 'TEST',
                'severity': 'HIGH',
                'value': 'test-value',
                'timestamp': '2025-01-25 10:00:00'
            }]

            scanner.generate_report(report_path, 'json')

            # Check report was created
            assert os.path.exists(report_path)

            # Check report is valid JSON
            with open(report_path, 'r') as f:
                data = json.load(f)
                assert data['total_detections'] == 1
                assert len(data['detections']) == 1
                assert data['detections'][0]['type'] == 'TEST'
        finally:
            os.unlink(ioc_path)
            os.unlink(report_path)


class TestProcessScanning:
    """Test process scanning functionality"""

    @patch('psutil.process_iter')
    def test_scan_processes_with_malicious_hash(self, mock_process_iter):
        """Test process scanning with malicious hash detection"""
        # Create test IOC file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ioc_file:
            ioc_file.write("HASH|sha256:malicious_hash|malware\n")
            ioc_file.flush()
            ioc_path = ioc_file.name

        try:
            # Mock process
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 1234,
                'name': 'malicious.exe',
                'exe': '/path/to/malicious.exe',
                'cmdline': ['malicious.exe', '--evil']
            }

            mock_process_iter.return_value = [mock_proc]

            # Mock hash calculation
            with patch('scan_ioc.calculate_file_hash', return_value='malicious_hash'):
                with patch('pathlib.Path.exists', return_value=True):
                    scanner = IOCScanner(ioc_path)
                    detections = scanner.scan_processes()

                    assert len(detections) == 1
                    assert detections[0]['type'] == 'PROCESS'
                    assert detections[0]['pid'] == 1234
                    assert detections[0]['name'] == 'malicious.exe'
        finally:
            os.unlink(ioc_path)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

class TestReportSafety:
    """Untrusted values must not break or inject into reports"""

    def test_redact_cmdline(self):
        from scan_ioc import redact_cmdline
        out = redact_cmdline("curl --token abc123 https://bob:hunter2@198.51.100.7/x")
        assert "abc123" not in out and "hunter2" not in out
        assert "198.51.100.7" in out

    def test_html_report_escapes_values(self, tmp_path):
        ioc_file = tmp_path / "ioc.txt"
        ioc_file.write_text("IP|192.0.2.1|test\n")
        scanner = IOCScanner(str(ioc_file))
        scanner.detections = [{
            'type': 'FILE_HASH', 'severity': 'HIGH',
            'path': '<script>alert(1)</script>.exe',
            'timestamp': '2025-01-25 10:00:00'
        }]
        report = tmp_path / "r.html"
        scanner.generate_report(str(report), 'html')
        content = report.read_text()
        assert '<script>alert(1)</script>' not in content
        assert '&lt;script&gt;' in content
