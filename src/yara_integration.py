"""
YARA Integration Module - Advanced pattern-based threat detection
Wraps yara-python for file scanning with custom rules
"""

import logging
import os
from pathlib import Path
from typing import List, Dict, Optional, Any

try:
    import yara
except ImportError:
    yara = None
    print("Warning: yara-python not installed. YARA scanning disabled.")


class YaraScanner:
    """YARA scanner for advanced malware detection patterns"""

    def __init__(self, rules_path: Optional[str] = None):
        # Initialize YARA scanner with compiled rules
        self.logger = logging.getLogger('YaraScanner')
        self.rules = None

        if not yara:
            self.logger.warning("YARA module not available - scanning disabled")
            return

        if rules_path:
            self.load_rules(rules_path)

    def load_rules(self, rules_path: str):
        """Compile and load YARA rules - pattern-based detection foundation"""
        if not yara:
            return

        try:
            if os.path.isfile(rules_path):
                # Single rules file
                self.rules = yara.compile(filepath=rules_path)
                self.logger.info(f"Loaded YARA rules from {rules_path}")

            elif os.path.isdir(rules_path):
                # Directory of rules
                rule_files = {}
                for rule_file in Path(rules_path).glob('*.yar'):
                    namespace = rule_file.stem
                    rule_files[namespace] = str(rule_file)

                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
                    self.logger.info(f"Loaded {len(rule_files)} YARA rule files")
                else:
                    self.logger.warning(f"No YARA rules found in {rules_path}")

        except yara.Error as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            raise

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with loaded YARA rules - detect complex patterns"""
        if not self.rules:
            return []

        matches = []

        try:
            # Run YARA scan
            yara_matches = self.rules.match(file_path)

            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'strings': []
                }

                # Extract matched strings
                for string in match.strings:
                    # Handle both old and new yara-python API
                    if hasattr(string, 'instances'):
                        # New API (yara-python 4.x)
                        for instance in string.instances:
                            match_info['strings'].append({
                                'identifier': string.identifier,
                                'offset': instance.offset,
                                'content': instance.matched_data[:100]  # Limit for display
                            })
                    else:
                        # Old API (yara-python 3.x)
                        for offset, identifier, data in string:
                            match_info['strings'].append({
                                'identifier': identifier,
                                'offset': offset,
                                'content': data[:100] if isinstance(data, bytes) else str(data)[:100]
                            })

                matches.append(match_info)
                self.logger.warning(f"YARA match: {match.rule} in {file_path}")

        except yara.Error as e:
            self.logger.error(f"YARA scan error on {file_path}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {file_path}: {e}")

        return matches

    def scan_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan raw data with YARA rules - memory/stream analysis"""
        if not self.rules:
            return []

        matches = []

        try:
            yara_matches = self.rules.match(data=data)

            for match in yara_matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'strings': []
                }

                for string in match.strings:
                    if hasattr(string, 'instances'):
                        for instance in string.instances:
                            match_info['strings'].append({
                                'identifier': string.identifier,
                                'offset': instance.offset,
                                'content': instance.matched_data[:100]
                            })
                    else:
                        for offset, identifier, data in string:
                            match_info['strings'].append({
                                'identifier': identifier,
                                'offset': offset,
                                'content': data[:100] if isinstance(data, bytes) else str(data)[:100]
                            })

                matches.append(match_info)

        except yara.Error as e:
            self.logger.error(f"YARA scan error on data: {e}")

        return matches

    def test_rules(self) -> bool:
        """Test if rules are loaded and valid - pre-flight check"""
        if not yara or not self.rules:
            return False

        try:
            # Test with empty data
            self.rules.match(data=b'test')
            return True
        except:
            return False

    def get_rule_count(self) -> int:
        """Get number of loaded rules for reporting"""
        if not self.rules:
            return 0

        # Note: yara-python doesn't provide direct rule count
        # This is an approximation
        try:
            test_matches = self.rules.match(data=b'')
            # This won't give actual count but indicates rules loaded
            return 1 if self.rules else 0
        except:
            return 0


class YaraRuleBuilder:
    """Helper class to build YARA rules programmatically"""

    @staticmethod
    def create_hash_rule(name: str, hash_value: str, hash_type: str = 'sha256') -> str:
        """Create YARA rule for hash-based detection"""
        rule = f"""
import "hash"

rule {name}
{{
    meta:
        description = "Hash-based detection rule"
        hash_{hash_type} = "{hash_value}"
        severity = "high"
        author = "SOC Team"

    condition:
        hash.{hash_type}(0, filesize) == "{hash_value}"
}}
"""
        return rule

    @staticmethod
    def create_string_rule(name: str, strings: List[str], description: str = "") -> str:
        """Create YARA rule for string-based detection"""
        string_defs = []
        for i, s in enumerate(strings):
            string_defs.append(f'        $str{i} = "{s}"')

        rule = f"""
rule {name}
{{
    meta:
        description = "{description or 'String-based detection rule'}"
        severity = "medium"
        author = "SOC Team"

    strings:
{chr(10).join(string_defs)}

    condition:
        any of them
}}
"""
        return rule

    @staticmethod
    def create_pe_rule(name: str) -> str:
        """Create YARA rule for PE file analysis"""
        rule = f"""
import "pe"

rule {name}
{{
    meta:
        description = "Suspicious PE file characteristics"
        severity = "medium"
        author = "SOC Team"

    condition:
        pe.is_pe and
        (
            pe.number_of_sections > 7 or
            pe.timestamp == 0 or
            pe.entry_point >= pe.sections[pe.number_of_sections - 1].virtual_address
        )
}}
"""
        return rule