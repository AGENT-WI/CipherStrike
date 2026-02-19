"""
SQL Injection Defense Analyzer
Analyzes SQL injection payloads for evasion techniques, WAF blocking reasons, and risk assessment.

Developed for ITSOLERA Educational Security Internship Project

PURPOSE:
  This module is designed for educational and defensive security research purposes only.
  It analyzes SQL injection payloads to help security professionals understand
  attack patterns, evasion techniques, and defensive strategies.

INTEGRATION:
  Integrates with payload generators that output labeled attack types:
  - boolean: Boolean-based blind SQL injection
  - error: Error-based SQL injection
  - union_version: UNION-based version disclosure
  - time_blind: Time-based blind SQL injection
  - schema_dump: Database schema extraction attempts

DISCLAIMER:
  This tool is provided for educational, defensive, and authorized security testing
  purposes only. Use this tool responsibly to improve application security and for
  authorized penetration testing with proper approval. Unauthorized access to computer
  systems is illegal and unethical.
  
  ITSOLERA and the contributors to this project assume no liability for misuse of
  this tool. By using this software, you agree to use it only for lawful purposes
  and in compliance with all applicable laws and regulations.

Copyright (c) 2026 ITSOLERA Educational Security Initiative
All rights reserved.
"""

# Module Information
MODULE_NAME = "SQLi Defense & Evasion Detector"
VERSION = "1.0.0"
AUTHOR = "Abdullah"

import re
import json
import os
from typing import Dict, List


class SQLiDefenseAnalyzer:
    """
    Analyzer for SQL injection payloads to detect evasion techniques and assess defense mechanisms.
    """
    
    def __init__(self):
        # Common SQL keywords that might indicate malicious activity
        self.sql_keywords = [
            'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
            'ALTER', 'EXEC', 'EXECUTE', 'DECLARE', 'CAST', 'CONVERT', 'CHAR',
            'VARCHAR', 'NCHAR', 'CONCAT', 'WAITFOR', 'DELAY', 'BENCHMARK',
            'SLEEP', 'LOAD_FILE', 'INTO', 'OUTFILE', 'DUMPFILE', 'INFORMATION_SCHEMA'
        ]
        
        # Evasion technique patterns with compiled regex
        # Each entry: (compiled_pattern, human_readable_label)
        self.evasion_patterns = {
            'case_manipulation': (
                # Detects mixed case SQL keywords like SeLeCt, uNiOn, InSeRt
                re.compile(r'\b[Ss][Ee][Ll][Ee][Cc][Tt]\b|\b[Uu][Nn][Ii][Oo][Nn]\b|'
                          r'\b[Ii][Nn][Ss][Ee][Rr][Tt]\b|\b[Dd][Ee][Ll][Ee][Tt][Ee]\b|'
                          r'\b[Dd][Rr][Oo][Pp]\b|\b[Ww][Hh][Ee][Rr][Ee]\b|'
                          r'\b[Ff][Rr][Oo][Mm]\b|\b[Aa][Nn][Dd]\b|\b[Oo][Rr]\b', re.IGNORECASE),
                'Case Manipulation'
            ),
            'inline_comment_abuse': (
                # Detects /**/ or /*!...*/ between or within keywords
                re.compile(r'/\*.*?\*/|\w+/\*\*/\w+|/\*!\d+', re.IGNORECASE),
                'Inline Comment Abuse'
            ),
            'url_encoding': (
                # Detects URL-encoded characters like %27, %20, %3D
                re.compile(r'%[0-9a-fA-F]{2}'),
                'URL Encoding'
            ),
            'double_encoding': (
                # Detects double URL encoding like %2527, %253D
                re.compile(r'%25[0-9a-fA-F]{2}'),
                'Double Encoding'
            ),
            'whitespace_abuse': (
                # Detects non-standard whitespace: tabs, newlines, carriage returns
                re.compile(r'[\t\n\r\v\f]|/\*\*/|\s{2,}'),
                'Whitespace Abuse'
            ),
            'hex_encoding': (
                # Detects hex encoding like 0x61646d696e or \\x41
                re.compile(r'0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2}', re.IGNORECASE),
                'Hex Encoding'
            ),
            'union_based_injection': (
                # Detects UNION SELECT patterns (case-insensitive)
                re.compile(r'\bUNION\b.*\bSELECT\b', re.IGNORECASE),
                'UNION-based Injection'
            ),
            'boolean_injection': (
                # Detects OR 1=1, AND 1=1, and similar boolean patterns
                re.compile(r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|"
                          r"['\"]?\s*(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
                          re.IGNORECASE),
                'Boolean Injection'
            ),
            'time_based_blind': (
                # Detects time-based blind SQLi: SLEEP(), pg_sleep(), WAITFOR DELAY
                re.compile(r'\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bWAITFOR\s+DELAY|'
                          r'\bpg_sleep\s*\(', re.IGNORECASE),
                'Time-based Blind'
            ),
            'comment_termination': (
                # Detects SQL comment termination with -- or #
                re.compile(r'(--|#)\s*$|--\s|\#'),
                'Comment Termination'
            )
        }
        
        # Mapping from evasion technique labels to WAF block reason explanations
        # This explains WHY a WAF would block each technique
        self.technique_to_waf_reason = {
            'Case Manipulation': "WAF normalizes payload to uppercase before scanning — mixed case trick fails",
            'Inline Comment Abuse': "WAF normalizes comments before scanning — /**/ trick fails on ModSecurity",
            'URL Encoding': "WAF decodes URL encoding before pattern matching — %27 becomes ' and triggers rules",
            'Double Encoding': "Modern WAFs recursively decode — %2527 becomes %27 becomes ' triggering quote detection",
            'Whitespace Abuse': "WAF strips/normalizes whitespace — extra spaces/tabs do not evade keyword detection",
            'Hex Encoding': "WAF converts hex literals to strings — 0x61646d696e becomes 'admin' and matches patterns",
            'UNION-based Injection': "WAF keyword blacklist triggers on UNION SELECT combination",
            'Boolean Injection': "WAF flags tautology patterns: OR 1=1 is a classic signature",
            'Time-based Blind': "WAF detects time-delay functions: SLEEP/pg_sleep/WAITFOR",
            'Comment Termination': "WAF detects SQL comment syntax -- and # used to neutralize query remainder"
        }
    
    def analyze(self, payload: str) -> Dict:
        """
        Analyze a SQL injection payload for evasion techniques and defense mechanisms.
        
        Args:
            payload: The SQL injection payload string to analyze
            
        Returns:
            Dictionary containing:
                - payload: The original payload string (echoed back for reference)
                - evasion_techniques_detected: List of detected evasion technique descriptions
                - waf_block_reasons: List of reasons why a WAF would block this payload
                - risk_level: One of "LOW", "MEDIUM", "HIGH"
                - defensive_notes: Human-readable explanation
        """
        evasion_techniques = []
        waf_block_reasons = []
        
        # === ENHANCED EVASION TECHNIQUE DETECTION ===
        
        # 1. Case Manipulation Detection (e.g., SeLeCt, uNiOn)
        sql_keywords_mixed_case = ['SELECT', 'UNION', 'INSERT', 'DELETE', 'DROP', 'WHERE', 'FROM', 'AND', 'OR']
        for keyword in sql_keywords_mixed_case:
            # Check if keyword exists with mixed case (not all upper or all lower)
            pattern = ''.join([f'[{c.lower()}{c.upper()}]' for c in keyword])
            matches = re.findall(pattern, payload)
            for match in matches:
                if match != match.upper() and match != match.lower():
                    evasion_techniques.append(f"Case manipulation detected: '{match}' (original: {keyword})")
                    waf_block_reasons.append(f"Mixed-case SQL keyword '{match}' bypasses simple pattern matching")
                    break
        
        # 2. Comment Insertion Detection (e.g., /*!SELECT*/, SE/**/LECT)
        # Inline comments breaking keywords
        if re.search(r'/\*.*?\*/', payload):
            evasion_techniques.append("Comment insertion detected: inline /*...*/ comments found")
            waf_block_reasons.append("Inline comments used to obfuscate SQL keywords and evade detection")
        
        # MySQL conditional comments
        if re.search(r'/\*!\d+', payload):
            evasion_techniques.append("MySQL conditional comment detected: /*!version*/ syntax")
            waf_block_reasons.append("MySQL version-specific comments used for selective code execution")
        
        # Comments splitting SQL keywords
        if re.search(r'\w+/\*\*/\w+', payload):
            evasion_techniques.append("Comment-split keywords detected: words separated by /**/ comments")
            waf_block_reasons.append("Comments used to split SQL keywords (e.g., SE/**/LECT) to bypass filters")
        
        # SQL line comments
        if re.search(r'--\s', payload) or re.search(r'#', payload):
            evasion_techniques.append("SQL line comments detected: -- or # syntax")
            waf_block_reasons.append("Line comments used to neutralize query remainder and bypass validation")
        
        # 3. URL Encoding Detection (e.g., %27 for quote, %20 for space)
        url_encoded_chars = re.findall(r'%[0-9a-fA-F]{2}', payload)
        if url_encoded_chars:
            # Decode common SQLi characters
            decoded_examples = []
            encoding_map = {'%27': "'", '%22': '"', '%20': ' ', '%3D': '=', '%3B': ';', 
                          '%2D': '-', '%2F': '/', '%28': '(', '%29': ')', '%3C': '<', 
                          '%3E': '>', '%7C': '|', '%26': '&'}
            for enc in url_encoded_chars[:5]:  # Check first 5
                if enc.upper() in encoding_map:
                    decoded_examples.append(f"{enc}->'{encoding_map[enc.upper()]}'")
            
            evasion_techniques.append(f"URL encoding detected: {len(url_encoded_chars)} encoded character(s) found")
            if decoded_examples:
                waf_block_reasons.append(f"URL-encoded characters bypass string matching: {', '.join(decoded_examples)}")
            else:
                waf_block_reasons.append(f"URL-encoded characters detected: {', '.join(url_encoded_chars[:3])}")
        
        # 4. Double Encoding Detection (e.g., %2527 = %27 = ')
        # Check for encoded percent signs
        if re.search(r'%25[0-9a-fA-F]{2}', payload):
            evasion_techniques.append("Double URL encoding detected: %25XX pattern (encoded percent sign)")
            waf_block_reasons.append("Double encoding bypasses WAFs that decode only once (e.g., %2527 -> %27 -> ')")
        
        # Check for multiple levels of encoding by counting % density
        percent_count = payload.count('%')
        if percent_count > 5:
            encoded_ratio = percent_count / len(payload) if len(payload) > 0 else 0
            if encoded_ratio > 0.15:  # More than 15% of payload is encoding
                evasion_techniques.append(f"Heavy URL encoding detected: {percent_count} percent signs suggest multiple encoding layers")
                waf_block_reasons.append("Excessive encoding indicates attempt to hide payload through multiple decode layers")
        
        # 5. Whitespace Abuse Detection (tabs, newlines instead of spaces)
        whitespace_chars = {
            '\t': 'tab',
            '\n': 'newline',
            '\r': 'carriage return',
            '\v': 'vertical tab',
            '\f': 'form feed'
        }
        detected_ws = []
        for ws_char, ws_name in whitespace_chars.items():
            if ws_char in payload:
                count = payload.count(ws_char)
                detected_ws.append(f"{ws_name}({count})")
        
        if detected_ws:
            evasion_techniques.append(f"Whitespace abuse detected: {', '.join(detected_ws)}")
            waf_block_reasons.append("Non-standard whitespace characters bypass space-based pattern matching")
        
        # Multiple consecutive spaces
        if re.search(r'  +', payload):  # 2 or more spaces
            evasion_techniques.append("Multiple consecutive spaces detected")
            waf_block_reasons.append("Multiple spaces used to evade fixed-width pattern matching")
        
        # 6. Hex Encoding Detection (e.g., 0x61646d696e for "admin")
        hex_literals = re.findall(r'0x[0-9a-fA-F]+', payload)
        if hex_literals:
            evasion_techniques.append(f"Hexadecimal encoding detected: {len(hex_literals)} hex literal(s) found")
            waf_block_reasons.append(f"Hex literals bypass string matching: {', '.join(hex_literals[:3])}")
            
            # Try to decode hex strings to show what they represent
            for hex_lit in hex_literals[:3]:
                try:
                    hex_value = hex_lit[2:]  # Remove '0x'
                    if len(hex_value) % 2 == 0:
                        decoded = bytes.fromhex(hex_value).decode('ascii', errors='ignore')
                        if decoded and decoded.isprintable():
                            evasion_techniques.append(f"Hex literal {hex_lit} decodes to: '{decoded}'")
                except:
                    pass
        
        # Alternative hex encoding with \\x notation
        if re.search(r'\\x[0-9a-fA-F]{2}', payload):
            evasion_techniques.append("Backslash-hex encoding detected: \\xXX notation")
            waf_block_reasons.append("Backslash-hex notation (\\xXX) used to encode characters")
        
        # 7. Scientific Notation Bypass (e.g., 1e0union, 1e1union)
        # Scientific notation followed by SQL keywords
        scientific_with_keywords = re.findall(r'\d+e\d+\s*[a-zA-Z]+', payload, re.IGNORECASE)
        if scientific_with_keywords:
            evasion_techniques.append(f"Scientific notation bypass detected: {', '.join(scientific_with_keywords[:3])}")
            waf_block_reasons.append("Scientific notation creates valid numbers that bypass keyword detection (e.g., 1e0=1)")
        
        # Scientific notation in general
        if re.search(r'\d+e[+-]?\d+', payload, re.IGNORECASE):
            evasion_techniques.append("Scientific notation usage: numbers in exponential format")
            waf_block_reasons.append("Exponential notation (e.g., 1e0) used to obfuscate numeric values")
        
        # Scientific notation with UNION (classic bypass)
        if re.search(r'\d+e\d+\s*(union|select|and|or)', payload, re.IGNORECASE):
            evasion_techniques.append("Scientific notation SQLi bypass: number directly adjacent to SQL keyword")
            waf_block_reasons.append("Classic bypass using scientific notation (1e0) to separate from SQL keywords")
        
        # === EXISTING DETECTION METHODS ===
        
        # Detect additional evasion techniques using helper method
        additional_techniques = self._detect_evasion_techniques(payload)
        evasion_techniques.extend(additional_techniques)
        
        # Map detected techniques to WAF block reasons
        for technique in additional_techniques:
            if technique in self.technique_to_waf_reason:
                waf_block_reasons.append(self.technique_to_waf_reason[technique])
        
        # Detect WAF blocking reasons using helper method
        additional_waf_reasons = self._detect_waf_triggers(payload)
        waf_block_reasons.extend(additional_waf_reasons)
        
        # Remove duplicates while preserving order
        evasion_techniques = list(dict.fromkeys(evasion_techniques))
        waf_block_reasons = list(dict.fromkeys(waf_block_reasons))
        
        # Calculate risk level based on number of detected techniques
        risk_level = self._calculate_risk_level(evasion_techniques)
        
        # Generate defensive notes
        defensive_notes = self._generate_defensive_notes(payload, evasion_techniques, waf_block_reasons, risk_level)
        
        return {
            "payload": payload,
            "evasion_techniques_detected": evasion_techniques,
            "waf_block_reasons": waf_block_reasons,
            "risk_level": risk_level,
            "defensive_notes": defensive_notes
        }
    
    def generate_defensive_notes(self, payload: str) -> str:
        """
        Generate comprehensive defensive notes for a SQL injection payload.
        
        This method provides educational information about the payload for defensive/research purposes only.
        References OWASP SQL Injection Prevention guidelines.
        
        OWASP SQL Injection Prevention Best Practices:
        - Defense Option 1: Use Prepared Statements (Parameterized Queries)
        - Defense Option 2: Use Stored Procedures (properly implemented)
        - Defense Option 3: Whitelist Input Validation
        - Defense Option 4: Escape All User Supplied Input
        
        Reference: https://owasp.org/www-community/attacks/SQL_Injection
        
        Args:
            payload: The SQL injection payload string to analyze
            
        Returns:
            A multi-line string with educational defensive information
        """
        # Analyze the payload first
        analysis = self.analyze(payload)
        
        notes = []
        notes.append("=" * 80)
        notes.append("SQL INJECTION DEFENSE ANALYSIS")
        notes.append("FOR EDUCATIONAL AND DEFENSIVE RESEARCH PURPOSES ONLY")
        notes.append("=" * 80)
        notes.append("")
        
        # Section 1: Payload Intent Analysis
        notes.append("1. PAYLOAD INTENT ANALYSIS")
        notes.append("-" * 80)
        notes.append(f"Payload: {payload}")
        notes.append(f"Length: {len(payload)} characters")
        notes.append(f"Risk Level: {analysis['risk_level']}")
        notes.append("")
        
        # Determine what the payload is attempting to do
        notes.append("What this payload is attempting to do:")
        
        payload_upper = payload.upper()
        attack_intents = []
        
        # Authentication bypass
        if re.search(r"('|\")?\s*(OR|AND)\s*('|\")?\s*['\"]?1['\"]?\s*=\s*['\"]?1", payload, re.IGNORECASE):
            attack_intents.append("  - Authentication Bypass: Classic '1'='1' or similar tautology to bypass login")
        elif re.search(r"'\s*(OR|AND)\s*['\"]", payload, re.IGNORECASE):
            attack_intents.append("  - Authentication Bypass: Boolean logic manipulation to circumvent authentication")
        
        # UNION-based data extraction
        if 'UNION' in payload_upper and 'SELECT' in payload_upper:
            attack_intents.append("  - Data Extraction: UNION-based SQLi to retrieve data from other tables")
        
        # Information gathering
        if 'INFORMATION_SCHEMA' in payload_upper:
            attack_intents.append("  - Information Gathering: Querying database metadata to map table/column structure")
        if re.search(r'\b(VERSION|DATABASE|USER|CURRENT_USER)\s*\(', payload, re.IGNORECASE):
            attack_intents.append("  - Information Gathering: Extracting database version, name, or user information")
        
        # Blind SQLi
        if re.search(r'SLEEP|BENCHMARK|WAITFOR|pg_sleep', payload, re.IGNORECASE):
            attack_intents.append("  - Time-Based Blind SQLi: Using time delays to infer data bit-by-bit")
        if re.search(r'\b(AND|OR)\b\s+\d+\s*[=<>]', payload, re.IGNORECASE):
            attack_intents.append("  - Boolean-Based Blind SQLi: Using true/false conditions to extract data")
        
        # Data manipulation
        if re.search(r'\b(INSERT|UPDATE|DELETE)\b', payload, re.IGNORECASE):
            attack_intents.append("  - Data Manipulation: Attempting to modify or delete database records")
        
        # Privilege escalation / destructive
        if re.search(r'\bDROP\b', payload, re.IGNORECASE):
            attack_intents.append("  - Destructive Attack: Attempting to drop tables or database objects")
        if re.search(r'\b(EXEC|EXECUTE|xp_cmdshell)\b', payload, re.IGNORECASE):
            attack_intents.append("  - Command Execution: Attempting to execute system commands or stored procedures")
        
        # File operations
        if re.search(r'LOAD_FILE|INTO\s+(OUT|DUMP)FILE', payload, re.IGNORECASE):
            attack_intents.append("  - File System Access: Attempting to read or write files on the server")
        
        # Stacked queries
        if re.search(r';\s*\w+', payload):
            attack_intents.append("  - Stacked Queries: Executing multiple SQL statements in sequence")
        
        # Comment-based bypass
        if re.search(r'--|\#|/\*', payload):
            attack_intents.append("  - Comment Injection: Using SQL comments to neutralize query logic")
        
        if attack_intents:
            notes.extend(attack_intents)
        else:
            notes.append("  - General SQL Injection: Attempting to manipulate SQL query logic")
        notes.append("")
        
        # Section 2: WAF/Filter Detection
        notes.append("2. WAF/FILTER RULES THAT WOULD CATCH THIS PAYLOAD")
        notes.append("-" * 80)
        
        if analysis['waf_block_reasons']:
            for i, reason in enumerate(analysis['waf_block_reasons'][:10], 1):
                notes.append(f"  Rule {i}: {reason}")
            if len(analysis['waf_block_reasons']) > 10:
                notes.append(f"  ... and {len(analysis['waf_block_reasons']) - 10} additional rules")
        else:
            notes.append("  - No obvious WAF triggers detected (may be benign or highly obfuscated)")
        notes.append("")
        
        # Specific WAF rule recommendations
        notes.append("Recommended WAF Rule Categories:")
        notes.append("  - SQL Keyword Blacklist: Block common SQL keywords (SELECT, UNION, DROP, etc.)")
        notes.append("  - Pattern Matching: Detect SQL injection patterns (quotes + logic operators)")
        notes.append("  - Comment Detection: Block SQL comment syntax (--, #, /* */)")
        notes.append("  - Encoding Detection: Normalize and decode multiple encoding layers")
        notes.append("  - Length Limits: Reject unusually long input strings")
        notes.append("  - Character Whitelist: Allow only expected characters for each input field")
        notes.append("")
        
        # Section 3: Evasion Techniques Used
        if analysis['evasion_techniques_detected']:
            notes.append("3. EVASION TECHNIQUES DETECTED")
            notes.append("-" * 80)
            for i, technique in enumerate(analysis['evasion_techniques_detected'][:15], 1):
                notes.append(f"  {i}. {technique}")
            if len(analysis['evasion_techniques_detected']) > 15:
                notes.append(f"  ... and {len(analysis['evasion_techniques_detected']) - 15} more techniques")
            notes.append("")
        
        # Section 4: Developer Defense Recommendations (OWASP-based)
        notes.append("4. DEVELOPER DEFENSE RECOMMENDATIONS (OWASP Best Practices)")
        notes.append("-" * 80)
        notes.append("")
        
        notes.append("PRIMARY DEFENSE (Required):")
        notes.append("  [+] Use Parameterized Queries (Prepared Statements)")
        notes.append("    - Separate SQL code from user data completely")
        notes.append("    - Example (Python): cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))")
        notes.append("    - Example (Java): PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?')")
        notes.append("    - Example (PHP): $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id')")
        notes.append("    - This is the MOST EFFECTIVE defense against SQL injection")
        notes.append("")
        
        notes.append("SECONDARY DEFENSES (Defense in Depth):")
        notes.append("  [+] Stored Procedures (if properly implemented)")
        notes.append("    - Use parameterized stored procedures, not dynamic SQL inside them")
        notes.append("    - Still vulnerable if stored procedure concatenates user input")
        notes.append("")
        
        notes.append("  [+] Whitelist Input Validation")
        notes.append("    - Validate input type, length, format, and range")
        notes.append("    - For numeric IDs: ensure input is actually a number")
        notes.append("    - For names: allow only alphanumeric and specific characters")
        notes.append("    - Reject any input that doesn't match expected pattern")
        notes.append("")
        
        notes.append("  [+] Principle of Least Privilege")
        notes.append("    - Database accounts should have minimal necessary permissions")
        notes.append("    - Web app should NOT connect as 'root' or 'sa'")
        notes.append("    - Separate accounts for read vs. write operations")
        notes.append("    - Disable dangerous functions (xp_cmdshell, LOAD_FILE, etc.)")
        notes.append("")
        
        notes.append("  [+] Escape User Input (Last Resort)")
        notes.append("    - Only if parameterized queries cannot be used")
        notes.append("    - Use database-specific escaping functions")
        notes.append("    - MySQL: mysqli_real_escape_string()")
        notes.append("    - PostgreSQL: pg_escape_string()")
        notes.append("    - WARNING: Escaping alone is NOT sufficient, use parameterized queries!")
        notes.append("")
        
        notes.append("ADDITIONAL SECURITY LAYERS:")
        notes.append("  [+] Web Application Firewall (WAF)")
        notes.append("    - ModSecurity with OWASP Core Rule Set")
        notes.append("    - Cloud WAF (Cloudflare, AWS WAF, Azure WAF)")
        notes.append("    - Note: WAF is NOT a substitute for secure coding")
        notes.append("")
        
        notes.append("  [+] Error Handling")
        notes.append("    - Never expose database errors to end users")
        notes.append("    - Log errors securely for debugging")
        notes.append("    - Return generic error messages to clients")
        notes.append("")
        
        notes.append("  [+] Security Testing")
        notes.append("    - Regular penetration testing")
        notes.append("    - Automated security scanning (SAST/DAST)")
        notes.append("    - Code review with security focus")
        notes.append("")
        
        # Section 5: References
        notes.append("5. REFERENCES & RESOURCES")
        notes.append("-" * 80)
        notes.append("  - OWASP SQL Injection Prevention Cheat Sheet:")
        notes.append("    https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
        notes.append("")
        notes.append("  - OWASP Top 10 - A03:2021 Injection:")
        notes.append("    https://owasp.org/Top10/A03_2021-Injection/")
        notes.append("")
        notes.append("  - CWE-89: SQL Injection:")
        notes.append("    https://cwe.mitre.org/data/definitions/89.html")
        notes.append("")
        notes.append("  - PortSwigger SQL Injection Guide:")
        notes.append("    https://portswigger.net/web-security/sql-injection")
        notes.append("")
        
        # Legal/ethical disclaimer
        notes.append("=" * 80)
        notes.append("DISCLAIMER")
        notes.append("-" * 80)
        notes.append("This analysis is provided for educational, defensive, and security research purposes")
        notes.append("only. Use this tool responsibly to improve application security and for authorized")
        notes.append("penetration testing. Unauthorized access to computer systems is illegal.")
        notes.append("=" * 80)
        
        return '\n'.join(notes)
    
    def _detect_evasion_techniques(self, payload: str) -> List[str]:
        """Detect evasion techniques in the payload using compiled regex patterns."""
        techniques = []
        
        # Loop through compiled regex patterns and check against payload
        for category, (compiled_pattern, label) in self.evasion_patterns.items():
            if compiled_pattern.search(payload):
                techniques.append(label)
        
        return list(set(techniques))  # Remove duplicates
    
    def _detect_waf_triggers(self, payload: str) -> List[str]:
        """Detect patterns that would trigger a WAF."""
        triggers = []
        
        # Check for SQL keywords
        payload_upper = payload.upper()
        detected_keywords = [kw for kw in self.sql_keywords if kw in payload_upper]
        if detected_keywords:
            triggers.append(f"SQL keywords detected: {', '.join(detected_keywords[:5])}" + 
                          (" and more" if len(detected_keywords) > 5 else ""))
        
        # Check for quote usage
        single_quotes = payload.count("'")
        double_quotes = payload.count('"')
        if single_quotes > 0 or double_quotes > 0:
            triggers.append(f"Quote characters detected ({single_quotes} single, {double_quotes} double)")
        
        # Check for SQL comment patterns
        if re.search(r'--|\#|/\*', payload):
            triggers.append("SQL comment syntax detected")
        
        # Check for semicolons (stacked queries)
        if ';' in payload:
            triggers.append("Semicolon detected (potential stacked query)")
        
        # Check for UNION attacks
        if re.search(r'\bUNION\b', payload, re.IGNORECASE):
            triggers.append("UNION keyword detected (classic SQLi pattern)")
        
        # Check for information schema access
        if re.search(r'INFORMATION_SCHEMA', payload, re.IGNORECASE):
            triggers.append("Information schema access attempt")
        
        # Check for database function calls
        db_functions = ['CONCAT', 'CHAR', 'ASCII', 'SUBSTRING', 'VERSION', 'DATABASE', 
                       'USER', 'SLEEP', 'BENCHMARK', 'LOAD_FILE']
        detected_functions = [func for func in db_functions if re.search(rf'\b{func}\b', payload, re.IGNORECASE)]
        if detected_functions:
            triggers.append(f"Database functions detected: {', '.join(detected_functions)}")
        
        # Check for suspicious operators
        if re.search(r'[=<>!]+', payload):
            triggers.append("Comparison operators detected")
        
        # Check for OR/AND logic
        if re.search(r'\b(OR|AND)\b', payload, re.IGNORECASE):
            triggers.append("Boolean logic operators detected")
        
        # Check for parentheses (function calls or subqueries)
        paren_count = payload.count('(')
        if paren_count > 0:
            triggers.append(f"Parentheses detected ({paren_count} opening)")
        
        # Check for alternative injection vectors
        if re.search(r'\$\{|\#\{', payload):
            triggers.append("Template/expression injection syntax")
        
        # Check for length anomalies
        if len(payload) > 100:
            triggers.append(f"Unusually long payload ({len(payload)} characters)")
        
        return triggers
    
    def _calculate_risk_level(self, evasion_techniques: List[str]) -> str:
        """Calculate the risk level based on number of detected evasion techniques.
        
        Args:
            evasion_techniques: List of detected evasion technique labels
            
        Returns:
            Risk level: 'LOW', 'MEDIUM', or 'HIGH'
            
        Risk Calculation:
            - 0 techniques -> LOW
            - 1-2 techniques -> MEDIUM
            - 3+ techniques -> HIGH
        """
        technique_count = len(evasion_techniques)
        
        if technique_count >= 3:
            return "HIGH"
        elif technique_count >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_defensive_notes(self, payload: str, evasion_techniques: List[str],
                                  waf_block_reasons: List[str], risk_level: str) -> str:
        """Generate human-readable defensive notes."""
        notes = []
        
        # Risk level summary
        notes.append(f"Risk Assessment: {risk_level}")
        
        # Evasion techniques summary
        if evasion_techniques:
            notes.append(f"\nEvasion Techniques: {len(evasion_techniques)} detected")
            notes.append("The attacker is attempting to bypass security filters using:")
            for technique in evasion_techniques[:5]:  # Limit to first 5
                notes.append(f"  - {technique}")
            if len(evasion_techniques) > 5:
                notes.append(f"  - ...and {len(evasion_techniques) - 5} more techniques")
        else:
            notes.append("\nEvasion Techniques: None detected (straightforward payload)")
        
        # WAF trigger summary
        if waf_block_reasons:
            notes.append(f"\nWAF Triggers: {len(waf_block_reasons)} potential block reasons")
            notes.append("A properly configured WAF should block this payload because:")
            for reason in waf_block_reasons[:5]:  # Limit to first 5
                notes.append(f"  - {reason}")
            if len(waf_block_reasons) > 5:
                notes.append(f"  - ...and {len(waf_block_reasons) - 5} more reasons")
        else:
            notes.append("\nWAF Triggers: Minimal indicators detected")
        
        # Recommendations
        notes.append("\nRecommendations:")
        if risk_level == "HIGH":
            notes.append("  - BLOCK immediately and log for security analysis")
            notes.append("  - Investigate the source IP for additional malicious activity")
            notes.append("  - Review application code for SQL injection vulnerabilities")
        elif risk_level == "MEDIUM":
            notes.append("  - Consider blocking and monitoring the source")
            notes.append("  - Implement parameterized queries in the application")
            notes.append("  - Enable detailed logging for forensic analysis")
        else:
            notes.append("  - Monitor for pattern escalation")
            notes.append("  - Ensure input validation is in place")
            notes.append("  - Use prepared statements and parameterized queries")
        
        # Payload characteristics
        notes.append(f"\nPayload Characteristics:")
        notes.append(f"  - Length: {len(payload)} characters")
        has_quotes = 'Yes' if any(q in payload for q in ["'", '"']) else 'No'
        notes.append(f"  - Contains quotes: {has_quotes}")
        notes.append(f"  - Contains SQL keywords: {'Yes' if any(kw in payload.upper() for kw in self.sql_keywords) else 'No'}")
        
        return '\n'.join(notes)


def run_sqli_defense_module(payload: str, output_format: str = "cli") -> None:
    """
    Run SQL injection defense analysis with different output formats.
    
    This function is designed to be called by the main CLI (Main.py) via --module sqli --defense flag.
    
    Args:
        payload: The SQL injection payload string to analyze
        output_format: Output format - "cli" (default), "json", or "txt"
            - "cli": Print formatted analysis results to console
            - "json": Print valid JSON string of the result dict
            - "txt": Write the result to sqli_defense_output.txt file
    
    Returns:
        None
    """
    analyzer = SQLiDefenseAnalyzer()
    
    if output_format.lower() == "cli":
        # CLI output with readable formatting
        result = analyzer.analyze(payload)
        
        print("=" * 80)
        print("SQL INJECTION DEFENSE ANALYSIS")
        print("=" * 80)
        print()
        
        print(f"Payload: {payload}")
        print(f"Risk Level: {result['risk_level']}")
        print()
        
        print("-" * 80)
        print(f"EVASION TECHNIQUES DETECTED: {len(result['evasion_techniques_detected'])}")
        print("-" * 80)
        if result['evasion_techniques_detected']:
            for i, technique in enumerate(result['evasion_techniques_detected'], 1):
                print(f"  {i}. {technique}")
        else:
            print("  None detected")
        print()
        
        print("-" * 80)
        print(f"WAF BLOCK REASONS: {len(result['waf_block_reasons'])}")
        print("-" * 80)
        if result['waf_block_reasons']:
            for i, reason in enumerate(result['waf_block_reasons'], 1):
                print(f"  {i}. {reason}")
        else:
            print("  No obvious WAF triggers detected")
        print()
        
        print("-" * 80)
        print("DEFENSIVE NOTES")
        print("-" * 80)
        print(result['defensive_notes'])
        print()
        print("=" * 80)
        
    elif output_format.lower() == "json":
        # JSON output
        result = analyzer.analyze(payload)
        # Add payload to the result for context
        result['payload'] = payload
        print(json.dumps(result, indent=2))
        
    elif output_format.lower() == "txt":
        # Text file output
        result = analyzer.analyze(payload)
        
        # Create outputs directory if it doesn't exist
        output_dir = "outputs"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        output_file = os.path.join(output_dir, "sqli_defense_output.txt")
        
        # Append to file (not overwrite)
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("SQL INJECTION DEFENSE ANALYSIS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Payload: {payload}\n")
            f.write(f"Risk Level: {result['risk_level']}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write(f"EVASION TECHNIQUES DETECTED: {len(result['evasion_techniques_detected'])}\n")
            f.write("-" * 80 + "\n")
            if result['evasion_techniques_detected']:
                for i, technique in enumerate(result['evasion_techniques_detected'], 1):
                    f.write(f"  {i}. {technique}\n")
            else:
                f.write("  None detected\n")
            f.write("\n")
            
            f.write("-" * 80 + "\n")
            f.write(f"WAF BLOCK REASONS: {len(result['waf_block_reasons'])}\n")
            f.write("-" * 80 + "\n")
            if result['waf_block_reasons']:
                for i, reason in enumerate(result['waf_block_reasons'], 1):
                    f.write(f"  {i}. {reason}\n")
            else:
                f.write("  No obvious WAF triggers detected\n")
            f.write("\n")
            
            f.write("-" * 80 + "\n")
            f.write("DEFENSIVE NOTES\n")
            f.write("-" * 80 + "\n")
            f.write(result['defensive_notes'] + "\n\n")
            f.write("=" * 80 + "\n")
        
        print(f"Analysis results written to: {output_file}")
        
    else:
        print(f"Error: Unknown output format '{output_format}'. Valid options: cli, json, txt")


def analyze_generator_output(generator_output: str) -> None:
    """
    Analyze a payload from SQLiGenerator educational output format.
    
    This function parses the formatted output from SQLiGenerator._format_educational_output()
    and runs the extracted payload through SQLiDefenseAnalyzer.
    
    Args:
        generator_output: Formatted string from SQLiGenerator with format:
                         "--- ITSOLERA EDUCATIONAL: TYPE (DB) ---\\nPayload: <payload>\\n[DISCLAIMER]..."
    
    Expected Format:
        --- ITSOLERA EDUCATIONAL: UNION_VERSION (MYSQL) ---
        Payload: ' UNION SELECT @@version --
        
        [DISCLAIMER]
        This payload is generated for EDUCATIONAL PURPOSES ONLY.
        ...
    """
    # Extract the payload line from the formatted output
    # Split on "Payload: " and take everything after it
    if "Payload: " not in generator_output:
        print("Error: Invalid generator output format. Missing 'Payload: ' line.")
        return
    
    # Split and extract the payload
    parts = generator_output.split("Payload: ")
    if len(parts) < 2:
        print("Error: Could not extract payload from generator output.")
        return
    
    # Get the payload line (everything after "Payload: " until the next newline)
    payload_section = parts[1]
    payload = payload_section.split('\n')[0].strip()
    
    # Extract the header info for display
    header_line = generator_output.split('\n')[0]
    
    # Analyze the payload
    analyzer = SQLiDefenseAnalyzer()
    result = analyzer.analyze(payload)
    
    # Print the analysis in a clean readable format
    print("=" * 80)
    print("ITSOLERA PAYLOAD ANALYSIS")
    print("=" * 80)
    print(f"\nSource: {header_line}")
    print(f"Payload: {payload}")
    print()
    print("-" * 80)
    print(f"RISK LEVEL: {result['risk_level']}")
    print("-" * 80)
    print()
    
    print(f"EVASION TECHNIQUES DETECTED: {len(result['evasion_techniques_detected'])}")
    if result['evasion_techniques_detected']:
        for i, technique in enumerate(result['evasion_techniques_detected'], 1):
            print(f"  {i}. {technique}")
    else:
        print("  (none detected)")
    print()
    
    print(f"WAF BLOCK REASONS: {len(result['waf_block_reasons'])}")
    if result['waf_block_reasons']:
        for i, reason in enumerate(result['waf_block_reasons'], 1):
            print(f"  {i}. {reason}")
    else:
        print("  (none detected)")
    print()
    
    print("DEFENSIVE NOTES:")
    print("-" * 80)
    print(result['defensive_notes'])
    print()
    print("=" * 80)
    print()


# Example usage and testing
if __name__ == "__main__":
    # Import SQLiGenerator from sqli_generator.py
    from sqli_generator import SQLiGenerator
    
    print("=" * 80)
    print("ITSOLERA EDUCATIONAL SECURITY PROJECT")
    print("SQL Injection Defense Analyzer - Generator Integration Test")
    print("=" * 80)
    print()
    
    # Initialize the payload generator
    generator = SQLiGenerator()
    
    # Test cases: (attack_type, database_type)
    test_cases = [
        ('union_version', 'mysql'),
        ('time_blind', 'postgresql'),
        ('boolean', 'mssql')
    ]
    
    print(f"Testing {len(test_cases)} payloads from SQLiGenerator...")
    print()
    
    # Generate and analyze each payload
    for attack_type, db_type in test_cases:
        # Generate the educational formatted output
        generator_output = generator.generate_educational(attack_type, db_type)
        
        # Analyze it using our new function
        analyze_generator_output(generator_output)
