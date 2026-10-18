"""
Utility functions for IOC scanning operations
Provides: hashing, validation, parsing, and logging utilities
"""

import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Union


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for SOC operations - visibility is key"""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    logger = logging.getLogger('IOCScanner')

    # Add file handler for audit trail
    file_handler = logging.FileHandler('ioc_scan.log')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    ))
    logger.addHandler(file_handler)

    return logger


def calculate_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> str:
    """Calculate file hash - fundamental for malware identification"""
    hash_func = getattr(hashlib, algorithm.lower())()

    try:
        with open(file_path, 'rb') as f:
            # Read in chunks for large files
            for chunk in iter(lambda: f.read(65536), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        raise Exception(f"Failed to hash file {file_path}: {e}")


def parse_ioc_line(line: str) -> Tuple[str, str, str]:
    """Parse IOC file line format: TYPE|VALUE|METADATA"""
    parts = line.split('|', 2)

    if len(parts) < 2:
        raise ValueError(f"Invalid IOC format: {line}")

    ioc_type = parts[0].strip().upper()
    value = parts[1].strip()
    metadata = parts[2].strip() if len(parts) > 2 else ""

    return ioc_type, value, metadata


def is_valid_ip(ip_str: str) -> bool:
    """Validate IPv4 address format - prevent false positives"""
    ip_pattern = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    return bool(ip_pattern.match(ip_str))


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format - ensure accurate detection"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,63}$'
    )
    return bool(domain_pattern.match(domain))


def is_valid_hash(hash_str: str, hash_type: str) -> bool:
    """Validate hash format based on type"""
    hash_lengths = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64
    }

    if hash_type not in hash_lengths:
        return False

    if len(hash_str) != hash_lengths[hash_type]:
        return False

    # Check if hexadecimal
    try:
        int(hash_str, 16)
        return True
    except ValueError:
        return False


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for reports - consistency in incident timelines"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')


def sanitize_path(path: str) -> str:
    """Sanitize file path for safe operations - security first"""
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>:"|?*]', '', path)

    # Prevent directory traversal
    sanitized = sanitized.replace('..', '')

    return sanitized


def extract_ips_from_text(text: str) -> list:
    """Extract IP addresses from text - useful for log parsing"""
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    return ip_pattern.findall(text)


def extract_domains_from_text(text: str) -> list:
    """Extract domain names from text - network IOC detection"""
    # Simplified domain extraction
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    return domain_pattern.findall(text)


def bytes_to_hex(data: bytes, separator: str = ' ') -> str:
    """Convert bytes to hex string - useful for binary analysis"""
    return separator.join(f'{b:02x}' for b in data)


def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate long strings for display - maintain readability"""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + '...'


def get_file_metadata(file_path: Union[str, Path]) -> dict:
    """Get file metadata for forensic context"""
    path = Path(file_path)

    if not path.exists():
        return {}

    stat = path.stat()

    return {
        'size': stat.st_size,
        'created': datetime.fromtimestamp(stat.st_ctime),
        'modified': datetime.fromtimestamp(stat.st_mtime),
        'accessed': datetime.fromtimestamp(stat.st_atime),
        'is_hidden': path.name.startswith('.'),
        'extension': path.suffix.lower()
    }


def severity_to_priority(severity: str) -> int:
    """Convert severity to numeric priority for sorting"""
    severity_map = {
        'CRITICAL': 1,
        'HIGH': 2,
        'MEDIUM': 3,
        'LOW': 4,
        'INFO': 5
    }
    return severity_map.get(severity.upper(), 99)