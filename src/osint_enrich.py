"""
OSINT Enrichment Module - Threat intelligence gathering
Provides context for IOCs via public APIs (VirusTotal, AbuseIPDB)
Note: API keys required for full functionality - never commit keys!
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, Optional, Any

try:
    import requests
except ImportError:
    requests = None
    print("Warning: requests not installed. OSINT enrichment disabled.")


class OSINTEnricher:
    """OSINT enrichment for IOCs - adds threat intelligence context"""

    def __init__(self, vt_api_key: Optional[str] = None, abuse_api_key: Optional[str] = None):
        # Initialize enricher with API keys from env or params
        self.logger = logging.getLogger('OSINTEnricher')

        # Load API keys from environment if not provided
        self.vt_api_key = vt_api_key or os.environ.get('VT_API_KEY')
        self.abuse_api_key = abuse_api_key or os.environ.get('ABUSEIPDB_API_KEY')

        # API endpoints
        self.vt_base_url = 'https://www.virustotal.com/api/v3'
        self.abuse_base_url = 'https://api.abuseipdb.com/api/v2'

        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = 1.0  # seconds

        if not requests:
            self.logger.warning("Requests module not available - enrichment disabled")

    def _rate_limit(self, service: str):
        """Implement rate limiting to respect API quotas"""
        current_time = time.time()
        last_time = self.last_request_time.get(service, 0)

        time_since_last = current_time - last_time
        if time_since_last < self.min_request_interval:
            time.sleep(self.min_request_interval - time_since_last)

        self.last_request_time[service] = time.time()

    def enrich_hash(self, file_hash: str) -> Dict[str, Any]:
        """Enrich file hash with VirusTotal data - malware intelligence"""
        if not self.vt_api_key or not requests:
            return {'error': 'VirusTotal API key not configured or requests not available'}

        try:
            self._rate_limit('virustotal')

            headers = {
                'x-apikey': self.vt_api_key
            }

            # Query VirusTotal for hash
            response = requests.get(
                f'{self.vt_base_url}/files/{file_hash}',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})

                # Extract relevant information
                enrichment = {
                    'source': 'VirusTotal',
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                    'first_seen': attributes.get('first_submission_date'),
                    'last_seen': attributes.get('last_modification_date'),
                    'file_type': attributes.get('type_description'),
                    'names': attributes.get('names', [])[:5],  # First 5 names
                    'tags': attributes.get('tags', []),
                    'threat_label': self._get_vt_threat_label(attributes)
                }

                return enrichment

            elif response.status_code == 404:
                return {'source': 'VirusTotal', 'status': 'not_found'}
            else:
                return {'source': 'VirusTotal', 'error': f'API error: {response.status_code}'}

        except requests.RequestException as e:
            self.logger.error(f"VirusTotal API error: {e}")
            return {'error': str(e)}

    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """Enrich IP address with AbuseIPDB data - threat reputation"""
        if not self.abuse_api_key or not requests:
            return {'error': 'AbuseIPDB API key not configured or requests not available'}

        try:
            self._rate_limit('abuseipdb')

            headers = {
                'Key': self.abuse_api_key,
                'Accept': 'application/json'
            }

            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90',
                'verbose': ''
            }

            response = requests.get(
                f'{self.abuse_base_url}/check',
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})

                enrichment = {
                    'source': 'AbuseIPDB',
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'usage_type': data.get('usageType'),
                    'isp': data.get('isp'),
                    'country': data.get('countryCode'),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt'),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'threat_categories': self._parse_abuse_categories(data.get('reports', []))
                }

                return enrichment

            else:
                return {'source': 'AbuseIPDB', 'error': f'API error: {response.status_code}'}

        except requests.RequestException as e:
            self.logger.error(f"AbuseIPDB API error: {e}")
            return {'error': str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with VirusTotal data - domain reputation"""
        if not self.vt_api_key or not requests:
            return {'error': 'VirusTotal API key not configured or requests not available'}

        try:
            self._rate_limit('virustotal')

            headers = {
                'x-apikey': self.vt_api_key
            }

            response = requests.get(
                f'{self.vt_base_url}/domains/{domain}',
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                attributes = data.get('attributes', {})

                enrichment = {
                    'source': 'VirusTotal',
                    'reputation': attributes.get('reputation', 0),
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'categories': attributes.get('categories', {}),
                    'last_dns_records': self._extract_dns_records(attributes),
                    'whois': attributes.get('whois'),
                    'popularity_ranks': attributes.get('popularity_ranks', {})
                }

                return enrichment

            elif response.status_code == 404:
                return {'source': 'VirusTotal', 'status': 'not_found'}
            else:
                return {'source': 'VirusTotal', 'error': f'API error: {response.status_code}'}

        except requests.RequestException as e:
            self.logger.error(f"VirusTotal domain API error: {e}")
            return {'error': str(e)}

    def _get_vt_threat_label(self, attributes: Dict) -> str:
        """Determine threat label from VirusTotal analysis"""
        stats = attributes.get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        if malicious > 10:
            return 'HIGH_THREAT'
        elif malicious > 5:
            return 'MEDIUM_THREAT'
        elif malicious > 0 or suspicious > 5:
            return 'LOW_THREAT'
        else:
            return 'CLEAN'

    def _parse_abuse_categories(self, reports: list) -> list:
        """Parse abuse categories from AbuseIPDB reports"""
        categories = set()

        for report in reports[:10]:  # Last 10 reports
            if 'categories' in report:
                categories.update(report['categories'])

        # Map category IDs to names (simplified)
        category_map = {
            3: 'Fraud',
            4: 'DDoS',
            9: 'Open Proxy',
            10: 'Web Spam',
            11: 'Email Spam',
            14: 'Port Scan',
            18: 'Brute Force',
            19: 'Bad Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH',
            23: 'IoT Malware'
        }

        return [category_map.get(cat, f'Category_{cat}') for cat in categories]

    def _extract_dns_records(self, attributes: Dict) -> Dict:
        """Extract relevant DNS records from domain data"""
        dns_records = {}

        if 'last_dns_records' in attributes:
            for record in attributes['last_dns_records']:
                record_type = record.get('type')
                if record_type in ['A', 'AAAA', 'MX', 'NS']:
                    if record_type not in dns_records:
                        dns_records[record_type] = []
                    dns_records[record_type].append(record.get('value'))

        return dns_records

    def enrich_ioc(self, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
        """Generic IOC enrichment dispatcher"""
        if ioc_type.upper() in ['HASH', 'MD5', 'SHA1', 'SHA256']:
            return self.enrich_hash(ioc_value)
        elif ioc_type.upper() == 'IP':
            return self.enrich_ip(ioc_value)
        elif ioc_type.upper() == 'DOMAIN':
            return self.enrich_domain(ioc_value)
        else:
            return {'error': f'Unsupported IOC type: {ioc_type}'}


class ThreatIntelligenceCache:
    """Simple cache for OSINT data to reduce API calls"""

    def __init__(self, cache_file: str = 'osint_cache.json', ttl_hours: int = 24):
        self.cache_file = cache_file
        self.ttl_hours = ttl_hours
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict:
        """Load cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2, default=str)
        except Exception as e:
            logging.error(f"Failed to save cache: {e}")

    def get(self, key: str) -> Optional[Dict]:
        """Get cached data if not expired"""
        if key in self.cache:
            entry = self.cache[key]
            timestamp = datetime.fromisoformat(entry['timestamp'])
            age_hours = (datetime.now() - timestamp).total_seconds() / 3600

            if age_hours < self.ttl_hours:
                return entry['data']

        return None

    def set(self, key: str, data: Dict):
        """Store data in cache"""
        self.cache[key] = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self._save_cache()