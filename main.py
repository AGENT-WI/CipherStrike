"""
Tool Name: CipherStrike - Offensive Security Payload Framework
File Name: main.py
Author: Team Epsilon
Description: A modular framework for generating and analyzing security payloads.
Strictly for educational and authorized defensive research.
"""

import argparse
import asyncio
import sys
import os

try:
    from modules.sqli.sqli_generator import SQLiGenerator
    from modules.sqli.sqli_defense import SQLiDefenseAnalyzer
    from modules.command_injection.command_injection import get_module as get_ci_module
    from modules.encoding.encoder import Encoder
    from modules.export.json_exporter import export_payloads_to_json
    from modules.export.txt_exporter import export_payloads_to_txt
    from modules.export.burp_exporter import export_burp_intruder_payloads
except ImportError as e:
    print(f"[!] Critical Error: Missing module file. \nDetails: {e}")
    sys.exit(1)

try:
    from modules.xss.xss_generator import run_scan as run_xss_scan
except ImportError:
    run_xss_scan = None

def print_banner():
    banner = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║               CIPHERSTRIKE PAYLOAD FRAMEWORK                 ║
    ║                Educational & Defensive Tool                  ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    parser = argparse.ArgumentParser(
        description="CipherStrike: A modular framework for security payload generation and analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Core Module Selection
    parser.add_argument("--module", choices=["xss", "sqli", "cmd"], required=True,
                        help="The vulnerability module to run")

    # SQLi Specific Flags
    parser.add_argument("--db", default="mysql", help="Target database")
    parser.add_argument("--type", default="union_version", help="Attack type")

    # Command Injection Specific Flags
    parser.add_argument("--os", choices=["unix", "windows", "all"], default="all")
    parser.add_argument("--attacker-ip", default="ATTACKER_IP",
                        help="Your IP for reverse shell payloads (e.g. 192.168.1.5)")
    parser.add_argument("--attacker-port", type=int, default=4444,
                        help="Your port for reverse shell payloads (default: 4444)")
    parser.add_argument("--min-confidence", type=int, default=0,
                        help="Minimum payload confidence score 0-100 (e.g. 80)")
    parser.add_argument("--waf", choices=["Cloudflare", "ModSecurity", "AWS WAF", "Akamai"],
                        help="Only return payloads that bypass this WAF")
    parser.add_argument("--severity", choices=["Low", "Medium", "High", "Critical"],
                        default="Low", help="Minimum severity level (default: Low)")
    parser.add_argument("--chain", choices=["unix_basic", "unix_blind", "unix_subshell",
                        "windows_basic", "shellshock", "ping_field"],
                        help="Print a specific attack chain (Recon -> Escalate -> Shell)")

    # XSS Specific Flags
    parser.add_argument("--url", help="Target URL for XSS scanning")
    parser.add_argument("--concurrency", type=int, default=10)

    # Encoding Flags
    parser.add_argument("--encode", choices=["url", "base64", "hex", "mixed"])

    # Output Flags
    parser.add_argument("--output", help="Path to save output")
    parser.add_argument("--format", choices=["json", "txt", "burp"], default="txt")

    args = parser.parse_args()
    print_banner()

    payload_results = []
    defense_info = None

    # --- SQL INJECTION MODULE ---
    if args.module == "sqli":
        gen = SQLiGenerator()
        print(f"[*] Generating {args.type} payload for {args.db}...")

        raw_output = gen.generate_template(args.type, args.db)
        raw_output = raw_output.replace("ITSOLERA", "CIPHERSTRIKE")

        if "Payload: " in raw_output:
            payload_str = raw_output.split("Payload: ")[1].split("\n")[0]
        else:
            payload_str = raw_output

        analyzer = SQLiDefenseAnalyzer()
        try:
            defense_info = analyzer.analyze(payload_str, attack_type=args.type)
        except TypeError:
            defense_info = analyzer.analyze(payload_str)

        payload_results.append({
            "template": payload_str,
            "full_block": raw_output,
            "module": "sqli",
            "db": args.db
        })

    # --- COMMAND INJECTION MODULE ---
    elif args.module == "cmd":
        print(f"[*] Fetching command injection payloads for OS : {args.os}")
        if args.waf:
            print(f"[*] WAF bypass filter   : {args.waf}")
        if args.min_confidence > 0:
            print(f"[*] Min confidence      : {args.min_confidence}%")
        if args.severity != "Low":
            print(f"[*] Min severity        : {args.severity}")
        if args.attacker_ip != "ATTACKER_IP":
            print(f"[*] Attacker IP         : {args.attacker_ip}:{args.attacker_port}")

        ci_instance = get_ci_module(
            target_os=args.os,
            attacker_ip=args.attacker_ip,
            attacker_port=args.attacker_port,
            min_confidence=args.min_confidence,
            min_severity=args.severity,
            waf_target=args.waf
        )

        # Chain mode — print the attack chain and exit
        if args.chain:
            ci_instance.print_chain(args.chain)
            return

        # Normal mode — get all filtered payloads
        payloads = ci_instance.get_payloads()

        if not payloads:
            print("[!] No payloads matched your filters. Try lowering --min-confidence or --severity.")
            sys.exit(0)

        print(f"[+] {len(payloads)} payloads matched your filters.\n")

        for p in payloads:
            payload_results.append({
                "template":   p['payload'],
                "module":     "cmd",
                "os":         args.os,
                "category":   p.get('category', 'injection'),
                "severity":   p.get('severity', 'N/A'),
                "confidence": p.get('confidence', 'N/A'),
                "waf_bypass": ", ".join(p.get('waf_bypasses', [])) or "None",
                "cve":        ", ".join(p.get('cve_refs', [])) or "N/A",
                "hint":       p.get('detection_hint', ''),
            })

    # --- XSS SCANNER MODULE ---
    elif args.module == "xss":
        if run_xss_scan is None:
            print("[!] XSS module is not available yet. Contact Waleed.")
            sys.exit(1)
        if not args.url:
            print("[!] Error: --url is required for XSS scanning")
            sys.exit(1)
        print(f"[*] Starting XSS scan on {args.url}...")
        asyncio.run(run_xss_scan(args.url, args.concurrency, args.output, verbose=True))
        return

    # --- APPLY ENCODING ---
    if args.encode and payload_results:
        encoder = Encoder()
        print(f"[*] Applying {args.encode} encoding to all payloads...")
        for item in payload_results:
            original = item['template']
            if args.encode == "url":     encoded = encoder.url_encode(original)
            elif args.encode == "base64": encoded = encoder.base64_encode(original)
            elif args.encode == "hex":   encoded = encoder.hex_encode(original)
            elif args.encode == "mixed": encoded = encoder.mixed_encode(original)
            item['template'] = encoded
            if "full_block" in item:
                item['full_block'] = item['full_block'].replace(original, encoded)

    # --- FINAL DISPLAY ---
    if payload_results:
        print("\n" + "="*65 + "\n GENERATED PAYLOADS \n" + "="*65)

        for p in payload_results:
            if p.get('module') == 'cmd':
                print(f"[{p['confidence']}%] [{p['severity']:<8}] [{p['category']:<14}] {p['template']}")
                if p.get('waf_bypass') != "None":
                    print(f"         WAF Bypass : {p['waf_bypass']}")
                if p.get('cve') != "N/A":
                    print(f"         CVE        : {p['cve']}")
                print(f"         Hint       : {p['hint']}\n")
            else:
                print(p.get('full_block', f"Payload: {p['template']}"))

        if defense_info:
            print("\n" + "="*65 + "\n DEFENSIVE ANALYSIS (CipherStrike Guard) \n" + "="*65)
            print(f"WAF Detection: {'[ BLOCKED ]' if defense_info.get('is_blocked') else '[ CLEAN ]'}")
            reasons = defense_info.get('waf_block_reasons', [])
            if reasons:
                print(f"Reasons: {', '.join(reasons)}")
            print(f"\nDefensive Notes:\n{defense_info.get('defensive_notes', 'N/A')}")
            print("="*65)

        if args.output:
            if args.format == "json":    export_payloads_to_json(payload_results, args.output)
            elif args.format == "burp":  export_burp_intruder_payloads(payload_results, args.output)
            else:                        export_payloads_to_txt(payload_results, args.output)
            print(f"\n[+] Results exported to: {args.output}")

if __name__ == "__main__":
    main()
