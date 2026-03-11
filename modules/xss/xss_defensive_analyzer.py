import re
import json

results = []

def detect_evasion(payload):

    techniques=[]

    if re.search(r'onerror|onload|onclick',payload,re.I):
        techniques.append("Event Handler Injection")

    if re.search(r'<script|<svg|<img|<body',payload,re.I):
        techniques.append("HTML Tag Injection")

    return techniques


def waf_detection(payload):

    reasons=[]

    if "<script>" in payload.lower():
        reasons.append("WAF detects script tag signature")

    if "onerror" in payload.lower():
        reasons.append("WAF detects event handler injection")

    if "alert(" in payload.lower():
        reasons.append("Suspicious JavaScript execution")

    return reasons


def analyze(payload):

    evasion=detect_evasion(payload)
    waf=waf_detection(payload)

    if len(evasion)>=2:
        risk="HIGH"
    elif len(evasion)==1:
        risk="MEDIUM"
    else:
        risk="LOW"

    print("\n===================================")
    print("PAYLOAD:",payload)
    print("RISK LEVEL:",risk)

    print("\nEVASION TECHNIQUES:",len(evasion))
    for e in evasion:
        print("-",e)

    print("\nWAF BLOCK REASONS:",len(waf))
    for w in waf:
        print("-",w)

    results.append({
        "payload":payload,
        "risk":risk,
        "evasion":evasion,
        "waf_detection":waf
    })


with open("data/generated_payloads.txt") as f:
    payloads=f.readlines()

for p in payloads:
    analyze(p.strip())

# save json report
with open("data/report.json","w") as f:
    json.dump(results,f,indent=4)

print("\nJSON report saved → data/report.json")
